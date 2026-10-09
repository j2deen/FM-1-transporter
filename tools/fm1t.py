#!/usr/bin/env python3
"""fm1t - Mac-side client for the FM-1 Transporter data channel.

    fm1t.py status
    fm1t.py uboot          (stock V15 -> UBOOT via the USB-MIDI soft key)
    fm1t.py rekey          (reboot the transporter into USB_KEY mode)
    fm1t.py runapp         (leave UBOOT and boot the installed firmware)
    fm1t.py info
    fm1t.py dump out.bin [--addr 0] [--len 0x100000] [--compare ref.bin]
    fm1t.py check FM-1.fwsc                (offline: is this the official V15 package?)
    fm1t.py write --package FM-1.fwsc --ref earlier-dump.bin [--write]
    fm1t.py selftest-write --ref earlier-dump.bin --sector 0x92000 [--write]
    fm1t.py ramrun IMAGE.bin [--addr 0x1C02000] [--clear A:N] [--poke A:V] [--read A:N]

`write` follows fm-1-research-lab's restore policy, and is a dry run unless
--write is given:
  1. the package must be the unmodified official V15 (FM-1.fwsc from M-VAVE,
     pinned by sha256 and checked here). Any other package must pass
     fm-1-research-lab's fm1_ota.require_reviewed (a PASSED hookcheck
     manifest; known-bad hashes refused);
  2. chip key 980F and flash 856014;
  3. a fresh full read must equal --ref over the package region;
  4. only differing 4 KiB sectors are written; none may lie below 0x4000;
     each is erased, written and read back by the firmware;
  5. a final full read must equal the expected image.
The firmware itself refuses any sector outside [0x4000, 0x93000).

info/dump/write enter UBOOT by themselves when stock V15 is running on the
transporter. A unit without working firmware needs the USB_KEY path: start
the transporter with the FM-1 off (or `rekey`), then switch the FM-1 on.
Requires pyserial. Writing the official V15 needs nothing else; writing any
other package also needs fm-1-research-lab (FM1_RESEARCH, default
~/fm-1-research-lab).
"""

import argparse
import binascii
import glob
import hashlib
import os
import struct
import sys
import time
import zlib

import serial

FLASH_SIZE = 0x100000


def find_port(explicit=None):
    candidates = [explicit] if explicit else sorted(glob.glob("/dev/cu.usbmodem*"))
    for path in candidates:
        try:
            s = serial.Serial(path, 115200, timeout=0.3)
        except serial.SerialException:
            continue
        s.reset_input_buffer()
        s.write(b"ping\n")
        deadline = time.time() + 1.0
        buf = b""
        while time.time() < deadline:
            buf += s.read(64)
            if b"PONG" in buf:
                s.timeout = 5
                return s
        s.close()
    sys.exit("fm1t: no FM-1 Transporter data port found")


def request(s, line, timeout=30):
    s.reset_input_buffer()
    s.write(line.encode() + b"\n")
    s.timeout = timeout
    reply = s.readline().decode(errors="replace").strip()
    if not reply:
        sys.exit(f"fm1t: no reply to '{line}'")
    return reply


def status(s):
    reply = request(s, "status")
    if not reply.startswith("OK"):
        sys.exit(f"fm1t: {reply}")
    return dict(kv.split("=") for kv in reply.split()[1:])


def ensure_uboot(s, timeout=20):
    """Make sure the FM-1 sits in UBOOT, using the soft key on stock V15."""
    st = status(s)
    if st["uboot"] == "1":
        return
    if st["v15"] != "1":
        sys.exit("fm1t: no UBOOT and no stock V15 on the transporter. Power the FM-1 on; "
                 "if it has no working firmware, run `fm1t.py rekey` and power-cycle it.")
    reply = request(s, "uboot")
    print(reply)
    if not reply.startswith("OK"):
        sys.exit(f"fm1t: {reply}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.5)
        if status(s)["uboot"] == "1":
            print("FM-1 is in UBOOT")
            return
    sys.exit("fm1t: soft key sent but no UBOOT appeared")


def cmd_status(s, _):
    print(request(s, "status"))


def cmd_uboot(s, _):
    ensure_uboot(s)


def cmd_runapp(s, _):
    print(request(s, "runapp"))


def cmd_rekey(s, _):
    print(request(s, "rekey"))
    print("transporter rebooting into USB_KEY mode; power-cycle the FM-1 now")


def cmd_info(s, _):
    ensure_uboot(s)
    reply = request(s, "info", timeout=30)
    print(reply)
    if reply.startswith("OK"):
        fields = dict(kv.split("=") for kv in reply.split()[1:])
        ok = fields.get("key") == "980F" and fields.get("id") == "856014"
        print("expected WL82 key 980F and flash 856014:", "yes" if ok else "NO")


def read_flash(s, addr, length, progress=True):
    reply = request(s, f"read {addr:#x} {length}", timeout=30)
    if not reply.startswith("DATA "):
        sys.exit(f"fm1t: {reply}")
    n = int(reply.split()[1])

    data = bytearray()
    s.timeout = 10
    while len(data) < n:
        chunk = s.read(min(65536, n - len(data)))
        if not chunk:
            sys.exit(f"fm1t: stalled at {len(data):#x} of {n:#x}")
        data += chunk
        if progress:
            print(f"\r{len(data) * 100 // n:3d}%  {len(data):#08x}", end="", flush=True)
    if progress:
        print()

    end = s.readline().decode(errors="replace").strip()
    crc = zlib.crc32(data) & 0xFFFFFFFF
    if end != f"END {crc:08X}":
        sys.exit(f"fm1t: transfer check failed ({end}, local {crc:08X})")
    return bytes(data)


def cmd_dump(s, args):
    ensure_uboot(s)
    addr, length = args.addr, args.len
    t0 = time.time()
    data = read_flash(s, addr, length)
    with open(args.out, "wb") as f:
        f.write(data)
    dt = time.time() - t0
    n = len(data)
    print(f"saved {args.out}: {n} bytes from {addr:#x}, crc32 {zlib.crc32(data) & 0xFFFFFFFF:08X}, "
          f"{dt:.1f} s ({n / dt / 1024:.0f} KiB/s)")

    if args.compare:
        compare(args.compare, addr, data)


APP_END = 0x93000   # [0, APP_END) is the V15 package region; must match exactly
SECTOR = 0x1000


def compare(ref_path, addr, data):
    """Per-4 KiB comparison. Past APP_END, V15 rewrites device data (VM/BTIF/USR),
    so differences there are reported, not treated as failures."""
    ref = open(ref_path, "rb").read()
    bad_app, changed_data = [], []
    for off in range(0, len(data), SECTOR):
        a = addr + off
        mine = data[off:off + SECTOR]
        theirs = ref[a:a + len(mine)]
        if len(theirs) < len(mine):
            break
        if mine != theirs:
            (bad_app if a < APP_END else changed_data).append(a)
    covered = min(len(data), max(0, len(ref) - addr))
    print(f"compared {covered:#x} bytes against {ref_path}")
    if bad_app:
        print(f"MISMATCH in [0, {APP_END:#x}): sectors " + " ".join(f"{a:#07x}" for a in bad_app))
    elif addr < APP_END:
        print(f"[{addr:#x}, {min(addr + covered, APP_END):#x}) identical")
    if changed_data:
        print(f"device-data sectors differing (normal after V15 runs): "
              + " ".join(f"{a:#07x}" for a in changed_data))
    elif addr + covered > APP_END:
        print(f"[{max(addr, APP_END):#x}, {addr + covered:#x}) identical")
    if bad_app:
        sys.exit(1)


WRITE_MIN = 0x4000     # flash header, SPL, isd_config below this: never written


# The unmodified official FM-1 V15 package (FM-1.fwsc from M-VAVE). The digest
# pins the whole file; the name of the file is not evidence.
STOCK_V15_SHA256 = "db1642b2b6fa5c2cccb11ffd13878068bb28601678d3644049f99dc40e7edb8a"
STOCK_V15_PRODUCT = "FM-1_015"
STOCK_V15_FLASH_AT = 1044          # file offset of its flash image

# .fwsc layout: a JieLi UFW container in which each of the first 20 blocks of
# 0x30 bytes ends in one identity byte (the product name). Without those 20
# bytes the file is the "logical" image, and the UFW offsets refer to that.
FWSC_MARKS, FWSC_STEP = 20, 0x30
UFW_HEAD, UFW_ENTRY = 0x40, 0x50
UFW_FLASH = 0                      # entry type of the raw flash image


def crc16(data):
    return binascii.crc_hqx(data, 0)       # CRC-16/XMODEM, as in docs/PROTOCOL.md


def jl_unmask(data, key=0xFFFF):
    """JieLi header mask: XOR with the low byte of a CRC-16 style key stream."""
    out = bytearray(data)
    for i in range(len(out)):
        out[i] ^= key & 0xFF
        key = ((key << 1) ^ (0x1021 if key & 0x8000 else 0)) & 0xFFFF
    return bytes(out)


def parse_fwsc(raw):
    """Return (flash image, product, file offset of the flash image) of an FM-1
    .fwsc, checking every CRC on the way. The flash image is the type-0 entry,
    byte-identical to raw flash from address 0. Raises ValueError."""
    marked = FWSC_MARKS * FWSC_STEP
    if len(raw) < marked:
        raise ValueError("too short for an FM-1 package")
    marks = raw[FWSC_STEP - 1:marked:FWSC_STEP]
    product = "".join(chr((m - i - 1) & 0xFF) for i, m in enumerate(marks) if m != 0x7D)
    table = b"".join(raw[i:i + FWSC_STEP - 1] for i in range(0, marked, FWSC_STEP))

    head = jl_unmask(table[:UFW_HEAD])
    head_crc, list_crc = struct.unpack_from("<HH", head, 0)
    count, = struct.unpack_from("<H", head, 8)
    if crc16(head[2:]) != head_crc:
        raise ValueError("UFW header CRC mismatch (not an FM-1 .fwsc)")
    end = UFW_HEAD + count * UFW_ENTRY
    if end > len(table):
        raise ValueError(f"UFW entry list too long ({count} entries)")
    if crc16(table[UFW_HEAD:end]) != list_crc:
        raise ValueError("UFW entry list CRC mismatch")

    for off in range(UFW_HEAD, end, UFW_ENTRY):
        typ, _, data_crc, _, data_off, size = struct.unpack_from(
            "<HHHHII", jl_unmask(table[off:off + UFW_ENTRY]), 0)
        if typ != UFW_FLASH:
            continue
        if data_off < len(table):
            raise ValueError("flash image overlaps the package header")
        start = data_off + FWSC_MARKS
        img = raw[start:start + size]
        if len(img) != size:
            raise ValueError("flash image runs past the end of the file")
        if crc16(img) != data_crc:
            raise ValueError("flash image CRC mismatch")
        return bytes(img), product, start
    raise ValueError("no flash image in the package")


def package_image(path):
    """Gate the package, then return its flash image (raw flash from address 0)
    and product name. The official V15 is checked here; any other package goes
    through fm-1-research-lab's review check."""
    raw = open(path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != STOCK_V15_SHA256:
        return reviewed_package_image(path, len(raw), digest)
    try:
        img, product, start = parse_fwsc(raw)
    except ValueError as e:
        sys.exit(f"fm1t: {path}: {e}")
    if product != STOCK_V15_PRODUCT or start != STOCK_V15_FLASH_AT or len(img) != APP_END:
        sys.exit(f"fm1t: {path}: official V15 digest but an unexpected layout "
                 f"({product!r}, flash image {len(img):#x} bytes at {start}); refusing")
    return img, product


def reviewed_package_image(path, size, digest):
    research = os.path.expanduser(os.environ.get("FM1_RESEARCH", "~/fm-1-research-lab"))
    sys.path.insert(0, os.path.join(research, "tools"))
    try:
        from fm1_ota import require_reviewed
        from fm1fw import Firmware
    except ImportError as e:
        sys.exit(f"fm1t: {path} is not the official V15 FM-1.fwsc ({size} bytes, sha256 {digest}; "
                 f"expected sha256 {STOCK_V15_SHA256}). Other packages need the review tools of "
                 f"fm-1-research-lab, not importable from {research} ({e}); refusing")
    require_reviewed(path)     # exits on known-bad or unreviewed packages
    fw = Firmware(open(path, "rb").read())
    e = next(e for e in fw.entries if e["type"] == 0)
    img = bytes(fw.raw[e["data_off"] + fw.skew:e["data_off"] + fw.skew + e["size"]])
    return img, fw.product


def cmd_check(args):
    """Offline: gate the package exactly as `write` does and describe it."""
    img, product = package_image(args.package)
    print(f"{args.package}: accepted, product {product}; flash image {len(img):#x} bytes, "
          f"sha256 {hashlib.sha256(img).hexdigest()[:16]}...")
    print(f"`write` would only ever touch [{WRITE_MIN:#x}, {len(img):#x})")


def cmd_write(s, args):
    img, product = package_image(args.package)
    ref = open(args.ref, "rb").read()
    if len(ref) != FLASH_SIZE or len(img) % SECTOR or len(img) > APP_END:
        sys.exit("fm1t: unexpected sizes (ref must be 1 MiB; image whole sectors within 0x93000)")
    diff = [a for a in range(0, len(img), SECTOR) if img[a:a + SECTOR] != ref[a:a + SECTOR]]
    print(f"package {product}: {len(img):#x} bytes, sha256 {hashlib.sha256(img).hexdigest()[:16]}...; "
          f"{len(diff)} sectors differ from --ref" + (": " + " ".join(f"{a:#07x}" for a in diff) if diff else ""))
    low = [a for a in diff if a < WRITE_MIN]
    if low:
        sys.exit(f"fm1t: refusing: package changes protected sectors below {WRITE_MIN:#x}: "
                 + " ".join(f"{a:#07x}" for a in low))

    ensure_uboot(s)
    reply = request(s, "info")
    print(reply)
    if reply != "OK key=980F type=3 id=856014":
        sys.exit("fm1t: chip key / flash id mismatch; aborting")

    print("reading full flash ...")
    now = read_flash(s, 0, FLASH_SIZE)
    n = len(img)
    bad = [a for a in range(0, n, SECTOR) if now[a:a + SECTOR] != ref[a:a + SECTOR]]
    if bad:
        sys.exit("fm1t: flash differs from --ref in package-region sectors "
                 + " ".join(f"{a:#07x}" for a in bad) + "; not writing")
    extra = [a for a in range(n, FLASH_SIZE, SECTOR) if now[a:a + SECTOR] != ref[a:a + SECTOR]]
    print("package region equals --ref; device-data sectors changed since --ref: "
          + (" ".join(f"{a:#07x}" for a in extra) if extra else "none"))

    if not args.write:
        print("dry run: nothing written (add --write to write "
              f"{len(diff)} sector{'s' if len(diff) != 1 else ''})")
        return
    if not diff:
        print("nothing to write: flash already holds this package")
        return

    for a in diff:
        reply = write_sector(s, a, img[a:a + SECTOR])
        print(f"sector {a:#07x}: {reply or 'no reply'}")
        if reply != "OK":
            sys.exit("fm1t: sector write failed; the FM-1 stays in UBOOT, re-run to retry")

    expect = img + now[n:]
    print("final full read ...")
    final = read_flash(s, 0, FLASH_SIZE)
    if final == expect:
        print("final full read EQUALS the expected image")
    else:
        bad = [a for a in range(0, FLASH_SIZE, SECTOR) if final[a:a + SECTOR] != expect[a:a + SECTOR]]
        sys.exit("fm1t: final read DIFFERS in sectors " + " ".join(f"{a:#07x}" for a in bad))


def write_sector(s, a, sec):
    s.reset_input_buffer()
    s.write(f"wsec {a:#x} {zlib.crc32(sec) & 0xFFFFFFFF:08X}\n".encode() + sec)
    s.timeout = 20
    return s.readline().decode(errors="replace").strip()


def cmd_selftest_write(s, args):
    """Rewrite one application sector with the bytes it already holds, to prove
    erase/write/verify end to end without changing the flash contents."""
    a = args.sector
    if a < WRITE_MIN or a >= APP_END or a % SECTOR:
        sys.exit(f"fm1t: sector must be 4 KiB aligned in [{WRITE_MIN:#x}, {APP_END:#x})")
    ref = open(args.ref, "rb").read()
    if len(ref) != FLASH_SIZE:
        sys.exit("fm1t: --ref must be a 1 MiB dump")

    ensure_uboot(s)
    reply = request(s, "info")
    print(reply)
    if reply != "OK key=980F type=3 id=856014":
        sys.exit("fm1t: chip key / flash id mismatch; aborting")

    print("reading full flash ...")
    before = read_flash(s, 0, FLASH_SIZE)
    if before[:APP_END] != ref[:APP_END]:
        sys.exit("fm1t: application area differs from --ref; not writing")
    sec = before[a:a + SECTOR]
    print(f"application area equals --ref; sector {a:#07x} sha256 {hashlib.sha256(sec).hexdigest()[:16]}...")

    if not args.write:
        print("dry run: nothing written (add --write to rewrite this sector with its own bytes)")
        return

    for attempt in range(1, 4):
        reply = write_sector(s, a, sec)
        print(f"sector {a:#07x} attempt {attempt}: {reply or 'no reply'}")
        if reply == "OK":
            break
    else:
        sys.exit("fm1t: sector rewrite failed; the FM-1 stays in UBOOT. Restore with "
                 "`fm1t.py write --package FM-1_v15.fwsc --ref <this dump> --write`")

    print("final full read ...")
    after = read_flash(s, 0, FLASH_SIZE)
    if after == before:
        print("final full read EQUALS the pre-write image: erase/write/verify works")
    else:
        bad = [x for x in range(0, FLASH_SIZE, SECTOR) if after[x:x + SECTOR] != before[x:x + SECTOR]]
        sys.exit("fm1t: final read DIFFERS in sectors " + " ".join(f"{x:#07x}" for x in bad))


def span(text):
    a, _, b = text.partition(":")
    return int(a, 0), int(b, 0)


def mem_write(s, addr, data):
    for off in range(0, len(data), 4096):
        chunk = data[off:off + 4096]
        s.reset_input_buffer()
        s.write(f"memw {addr + off:#x} {len(chunk)} {zlib.crc32(chunk) & 0xFFFFFFFF:08X}\n".encode()
                + chunk)
        s.timeout = 20
        reply = s.readline().decode(errors="replace").strip()
        if reply != "OK":
            sys.exit(f"fm1t: memw {addr + off:#x}: {reply or 'no reply'}")


def mem_read(s, addr, length):
    out = bytearray()
    for off in range(0, length, 4096):
        n = min(4096, length - off)
        reply = request(s, f"memr {addr + off:#x} {n}", timeout=20)
        if reply != f"DATA {n}":
            sys.exit(f"fm1t: memr {addr + off:#x}: {reply}")
        s.timeout = 10
        data = s.read(n)
        end = s.readline().decode(errors="replace").strip()
        if len(data) != n or end != f"END {zlib.crc32(data) & 0xFFFFFFFF:08X}":
            sys.exit(f"fm1t: memr {addr + off:#x}: transfer check failed ({end})")
        out += data
    return bytes(out)


def cmd_ramrun(s, args):
    """Load a RAM image through the ROM UBOOT1.00 and call it (no loader, no
    flash access). Same semantics as fm-1-research-lab tools/fm1_ramrun.py."""
    ensure_uboot(s)
    if status(s).get("loader_running") == "1":
        sys.exit("fm1t: the flash loader is running (it occupies 0x1C02000); RAM-run needs a "
                 "fresh ROM UBOOT session. Reset the FM-1 into UBOOT again first.")
    img = open(args.image, "rb").read()
    for a, n in args.clear:
        mem_write(s, a, bytes(n))
    for a, v in args.poke:
        mem_write(s, a, (v & 0xFFFFFFFF).to_bytes(4, "little"))
    mem_write(s, args.addr, img)
    back = mem_read(s, args.addr, len(img))
    print(f"loaded {len(img)} B at {args.addr:#x}; read-back {'OK' if back == img else 'MISMATCH'}")
    if back != img:
        sys.exit("fm1t: image read-back mismatch; not jumping")
    reply = request(s, f"jump {args.addr:#x} {args.arg:#x}", timeout=20)
    print(f"jump({args.addr:#x}, arg={args.arg:#06x}): {reply}")
    if not reply.startswith("OK"):
        sys.exit(1)
    for a, n in args.read:
        data = mem_read(s, a, n)
        for off in range(0, n, 16):
            print(f"  {a + off:08x}: {data[off:off + 16].hex(' ')}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", help="data port (default: probe /dev/cu.usbmodem*)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("uboot")
    sub.add_parser("rekey")
    sub.add_parser("runapp")
    sub.add_parser("info")
    d = sub.add_parser("dump")
    d.add_argument("out")
    d.add_argument("--addr", type=lambda x: int(x, 0), default=0)
    d.add_argument("--len", type=lambda x: int(x, 0), default=FLASH_SIZE)
    d.add_argument("--compare", help="reference image to compare against")
    c = sub.add_parser("check")
    c.add_argument("package", help=".fwsc to check, with no transporter connected")
    w = sub.add_parser("write")
    w.add_argument("--package", required=True, help=".fwsc whose flash image is written")
    w.add_argument("--ref", required=True, help="earlier full dump; a fresh read must equal it")
    w.add_argument("--write", action="store_true", help="actually write (default: dry run)")
    t = sub.add_parser("selftest-write")
    t.add_argument("--ref", required=True, help="earlier full dump; the app area must equal it")
    t.add_argument("--sector", type=lambda x: int(x, 0), required=True)
    t.add_argument("--write", action="store_true", help="actually rewrite (default: dry run)")
    r = sub.add_parser("ramrun")
    r.add_argument("image")
    r.add_argument("--addr", type=lambda x: int(x, 0), default=0x1C02000)
    r.add_argument("--arg", type=lambda x: int(x, 0), default=0)
    r.add_argument("--clear", type=span, action="append", default=[])
    r.add_argument("--poke", type=span, action="append", default=[])
    r.add_argument("--read", type=span, action="append", default=[])
    args = ap.parse_args()

    if args.cmd == "check":
        return cmd_check(args)
    s = find_port(args.port)
    {"status": cmd_status, "uboot": cmd_uboot, "rekey": cmd_rekey, "runapp": cmd_runapp, "info": cmd_info, "dump": cmd_dump, "write": cmd_write,
     "selftest-write": cmd_selftest_write, "ramrun": cmd_ramrun}[args.cmd](s, args)


if __name__ == "__main__":
    main()
