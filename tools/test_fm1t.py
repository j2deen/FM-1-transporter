#!/usr/bin/env python3
"""Offline tests for fm1t.py: the .fwsc package gate and the `write` flow
against a simulated transporter. No hardware and no real firmware needed.

    python3 tools/test_fm1t.py
"""

import contextlib
import hashlib
import io
import os
import struct
import sys
import tempfile
import types
import zlib

sys.modules.setdefault("serial", types.ModuleType("serial"))     # pyserial is not needed here
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fm1t  # noqa: E402

FAILED = []


def ok(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        FAILED.append(what)


def mask(data, key=0xFFFF):
    return fm1t.jl_unmask(data, key)        # the mask is its own inverse


def build_fwsc(flash, product="FM-1_015", extra=b"\x55" * 300):
    """A minimal .fwsc: UFW header, two entries (flash, type 100), identity bytes."""
    files = [(0, b"flash.bin", flash), (100, b"ota.bin", extra)]
    off, entries, placed = 0x400, b"", []
    for i, (typ, name, data) in enumerate(files):
        off = (off + 0xFF) & ~0xFF
        e = bytearray(fm1t.UFW_ENTRY)
        struct.pack_into("<HHHHIII", e, 0, typ, i, fm1t.crc16(data), 0, off, len(data), (len(data) + 31) & ~31)
        e[0x40:0x40 + len(name)] = name
        entries += mask(bytes(e))
        placed.append((off, data))
        off += len(data)
    head = bytearray(fm1t.UFW_HEAD)
    struct.pack_into("<IH", head, 4, off, len(files))
    struct.pack_into("<H", head, 2, fm1t.crc16(entries))
    struct.pack_into("<H", head, 0, fm1t.crc16(bytes(head[2:])))
    logical = bytearray(b"\xFF" * off)
    logical[:fm1t.UFW_HEAD] = mask(bytes(head))
    logical[fm1t.UFW_HEAD:fm1t.UFW_HEAD + len(entries)] = entries
    for o, data in placed:
        logical[o:o + len(data)] = data
    keep = fm1t.FWSC_STEP - 1
    raw = bytearray()
    for i in range(fm1t.FWSC_MARKS):
        m = (ord(product[i]) + i + 1) & 0xFF if i < len(product) else 0x7D
        raw += logical[i * keep:(i + 1) * keep] + bytes([m])
    return bytes(raw + logical[fm1t.FWSC_MARKS * keep:])


def stock_like_flash():
    """0x93000 bytes of distinct, position-dependent content."""
    return b"".join(hashlib.sha256(struct.pack("<I", i)).digest() for i in range(fm1t.APP_END // 32))


def exits(fn, *a):
    """Run fn; return (exit message or None, stdout)."""
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            fn(*a)
    except SystemExit as e:
        return str(e.code), out.getvalue()
    return None, out.getvalue()


class FakeTransporter:
    """The fm1t line protocol on CDC 1, backed by a 1 MiB flash image."""

    def __init__(self, flash):
        self.flash = bytearray(flash)
        self.rx = b""
        self.timeout = 1
        self.written = []

    def reset_input_buffer(self):
        self.rx = b""

    def write(self, data):
        line, _, body = data.partition(b"\n")
        w = line.decode().split()
        if w[0] == "status":
            self.rx += b"OK uboot=1 v15=0 loader_running=1\n"
        elif w[0] == "info":
            self.rx += b"OK key=980F type=3 id=856014\n"
        elif w[0] == "read":
            a, n = int(w[1], 0), int(w[2])
            d = bytes(self.flash[a:a + n])
            self.rx += f"DATA {n}\n".encode() + d + f"END {zlib.crc32(d) & 0xFFFFFFFF:08X}\n".encode()
        elif w[0] == "wsec":
            a = int(w[1], 0)
            # the firmware's own guard (src/jieli_uboot.c): whole sectors in [0x4000, 0x93000)
            if a % 0x1000 or a < 0x4000 or a >= 0x93000 or len(body) != 0x1000:
                self.rx += b"ERR range\n"
            elif f"{zlib.crc32(body) & 0xFFFFFFFF:08X}" != w[2]:
                self.rx += b"ERR crc\n"
            else:
                self.flash[a:a + 0x1000] = body
                self.written.append(a)
                self.rx += b"OK\n"
        else:
            self.rx += b"ERR unknown\n"

    def read(self, n):
        d, self.rx = self.rx[:n], self.rx[n:]
        return d

    def readline(self):
        i = self.rx.find(b"\n") + 1
        d, self.rx = self.rx[:i], self.rx[i:]
        return d


def main():
    tmp = tempfile.mkdtemp()

    def save(name, data):
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    # --- format ---
    ok(fm1t.crc16(b"123456789") == 0x31C3, "crc16 is CRC-16/XMODEM")
    flash = stock_like_flash()
    pkg = build_fwsc(flash)
    img, product, start = fm1t.parse_fwsc(pkg)
    ok(img == flash and product == "FM-1_015" and start == fm1t.STOCK_V15_FLASH_AT,
       "parse_fwsc: flash image, product and offset 1044")

    def rejects(raw, word, what):
        try:
            fm1t.parse_fwsc(raw)
            ok(False, what)
        except ValueError as e:
            ok(word in str(e), f"{what} ({e})")

    bad = bytearray(pkg); bad[5000] ^= 1
    rejects(bytes(bad), "flash image CRC", "one flipped bit in the flash image is refused")
    bad = bytearray(pkg); bad[3] ^= 1
    rejects(bytes(bad), "header CRC", "a damaged UFW header is refused")
    bad = bytearray(pkg); bad[0x60] ^= 1
    rejects(bytes(bad), "entry list CRC", "a damaged entry list is refused")
    rejects(pkg[:100000], "past the end", "a truncated package is refused")
    rejects(b"\0" * 100, "too short", "a tiny file is refused")

    # --- gate ---
    path = save("FM-1.fwsc", pkg)
    os.environ["FM1_RESEARCH"] = os.path.join(tmp, "no-such-research-lab")
    msg, _ = exits(fm1t.package_image, path)
    ok(msg is not None and "not the official V15" in msg, "a package with another digest is refused")

    real_sha = fm1t.STOCK_V15_SHA256
    fm1t.STOCK_V15_SHA256 = hashlib.sha256(pkg).hexdigest()      # treat the test package as "official"
    try:
        msg, out = exits(lambda: print(fm1t.package_image(path)[1]))
        ok(msg is None and out.strip() == "FM-1_015", "the pinned digest is accepted")

        odd = build_fwsc(flash, product="FM-1_016")
        fm1t.STOCK_V15_SHA256 = hashlib.sha256(odd).hexdigest()
        msg, _ = exits(fm1t.package_image, save("odd.fwsc", odd))
        ok(msg is not None and "unexpected layout" in msg, "pinned digest with another layout is refused")
        fm1t.STOCK_V15_SHA256 = hashlib.sha256(pkg).hexdigest()

        # --- write: a unit whose application area is corrupted ---
        device_data = os.urandom(fm1t.FLASH_SIZE - fm1t.APP_END)
        broken = bytearray(flash + device_data)
        for a in (0x4000, 0x21000, 0x92000):
            broken[a:a + 0x1000] = os.urandom(0x1000)
        ref = save("backup.bin", bytes(broken))
        args = types.SimpleNamespace(package=path, ref=ref, write=False)

        dev = FakeTransporter(broken)
        msg, out = exits(fm1t.cmd_write, dev, args)
        ok(msg is None and "dry run" in out and "3 sectors differ" in out and not dev.written,
           "dry run: lists 3 sectors, writes nothing")

        args.write = True
        msg, out = exits(fm1t.cmd_write, dev, args)
        ok(msg is None and dev.written == [0x4000, 0x21000, 0x92000], "write: only the 3 differing sectors")
        ok(bytes(dev.flash) == flash + device_data and "EQUALS" in out,
           "write: flash is the package image, device data untouched")

        # --- write refuses what it must ---
        boot = bytearray(broken); boot[0x1000] ^= 0xFF
        args.ref = save("boot.bin", bytes(boot))
        dev = FakeTransporter(boot)
        msg, _ = exits(fm1t.cmd_write, dev, args)
        ok(msg is not None and "protected sectors" in msg and not dev.written,
           "damage below 0x4000: refused, nothing written")

        moved = bytearray(broken); moved[0x30000] ^= 0xFF
        args.ref = ref
        dev = FakeTransporter(moved)
        msg, _ = exits(fm1t.cmd_write, dev, args)
        ok(msg is not None and "differs from --ref" in msg and not dev.written,
           "flash changed since the dump: refused, nothing written")
    finally:
        fm1t.STOCK_V15_SHA256 = real_sha

    print(f"\n{'FAILED: ' + str(len(FAILED)) if FAILED else 'all passed'}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
