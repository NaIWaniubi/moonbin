#!/usr/bin/env python3
"""LIEF cross-check oracle for moonbin's Mach-O parser (src/macho).

The MoonBit tests in src/macho/macho_test.mbt build two deterministic Mach-O
files (Mach-O64 little-endian x86-64 with LC_MAIN, Mach-O32 big-endian PowerPC
with LC_UNIXTHREAD) and print their exact bytes as hex lines tagged
"MACHOCROSS". This script:

  1. runs `moon test src/macho` and requires an all-green summary,
  2. decodes those hex lines into the exact bytes the golden tests assert on,
  3. regenerates the same fixtures independently in Python and requires
     byte-for-byte identity with the MoonBit dump (so LIEF and MoonBit are
     provably looking at the same bytes),
  4. parses them with LIEF and compares header / segments / sections /
     symbols / dylibs / entry against the same values the golden tests assert.

No host execution of the fixtures happens: LIEF only reads them.

Usage (from the worktree root):
  python -I test/macho_crosscheck.py

Note on entry: for the 64-bit LC_MAIN fixture LIEF's `entrypoint` already
resolves the file offset to a virtual address, so it is compared directly.
For the 32-bit big-endian LC_UNIXTHREAD fixture LIEF 0.16.4 mis-extracts the
convenience `entrypoint`/`pc` (it reads the big-endian PPC thread state as
little-endian), so the entry is instead read from LIEF's raw
`thread_command.state` bytes per the PPC ABI (srr0 = first big-endian u32),
which is exactly what the MoonBit parser does.
"""
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import lief

try:
    lief.logging.set_level(lief.logging.LEVEL.CRITICAL)
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent

CHECKS = 0
FAILED = 0


def expect(ok, label):
    global CHECKS, FAILED
    CHECKS += 1
    if ok:
        print(f"  ok: {label}")
    else:
        FAILED += 1
        print(f"  MISMATCH: {label}", file=sys.stderr)


def iv(x):
    """LIEF exposes some header fields as enums; normalize to int."""
    v = getattr(x, "value", x)
    try:
        return int(v)
    except Exception:
        return v


# ---------------------------------------------------------------------------
# Independent Python regeneration of the two fixtures (must match the MoonBit
# builders in src/macho/macho_test.mbt byte for byte).
# ---------------------------------------------------------------------------
def build_macho64le():
    dylib_name = b"/usr/lib/libSystem.B.dylib\0"
    dylib_cmdsize = ((24 + len(dylib_name)) + 7) & ~7
    hdr_size = 32
    seg_cmdsize = 72 + 80
    sizeofcmds = seg_cmdsize + 24 + dylib_cmdsize + 24
    text_off = hdr_size + sizeofcmds
    text = bytes([0x55, 0x48, 0x89, 0xE5])
    symtab_off = text_off + len(text)
    strtab_off = symtab_off + 2 * 16
    strtab = b"\0_main\0_printf\0"
    total = strtab_off + len(strtab)
    base = 0x100000000
    text_addr = base + text_off
    buf = bytearray()
    buf += struct.pack("<IiiIIII", 0xFEEDFACF, 0x01000007, 3, 2, 4, sizeofcmds, 0)
    buf += struct.pack("<I", 0)
    seg = bytearray()
    seg += struct.pack("<II", 0x19, seg_cmdsize)
    seg += b"__TEXT\0".ljust(16, b"\0")
    seg += struct.pack("<QQQQ", base, 0x1000, 0, total)
    seg += struct.pack("<ii", 7, 5)
    seg += struct.pack("<II", 1, 0)
    sec = bytearray()
    sec += b"__text\0".ljust(16, b"\0")
    sec += b"__TEXT\0".ljust(16, b"\0")
    sec += struct.pack("<QQ", text_addr, 4)
    sec += struct.pack("<IIIIIIII", text_off, 0, 0, 0, 0x80000400, 0, 0, 0)
    seg += sec
    buf += seg
    buf += struct.pack("<IIIIII", 0x2, 24, symtab_off, 2, strtab_off, len(strtab))
    d = bytearray()
    d += struct.pack("<II", 0xC, dylib_cmdsize)
    d += struct.pack("<IIII", 24, 0, 0, 0)
    d += dylib_name
    buf += d.ljust(dylib_cmdsize, b"\0")
    buf += struct.pack("<IIQQ", 0x80000028, 24, text_off, 0)
    buf += text
    buf += struct.pack("<IBBHQ", 1, 0x0F, 1, 0, text_addr)
    buf += struct.pack("<IBBHQ", 7, 0x01, 0, 0, 0)
    buf += strtab
    assert len(buf) == total
    return bytes(buf)


def build_macho32be():
    dylib_name = b"/usr/lib/libSystem.B.dylib\0"
    dylib_cmdsize = ((24 + len(dylib_name)) + 7) & ~7
    hdr_size = 28
    seg_cmdsize = 56 + 68
    thread_count = 40
    thread_cmdsize = 16 + thread_count * 4
    sizeofcmds = seg_cmdsize + 24 + dylib_cmdsize + thread_cmdsize
    text_off = hdr_size + sizeofcmds
    text = bytes([0x7C, 0x08, 0x02, 0xA6])
    symtab_off = text_off + 4
    strtab_off = symtab_off + 2 * 12
    strtab = b"\0_main\0_printf\0"
    total = strtab_off + len(strtab)
    base = 0x1000
    text_addr = base + text_off
    buf = bytearray()
    buf += struct.pack(">IiiIIII", 0xFEEDFACE, 18, 0, 2, 4, sizeofcmds, 0)
    seg = bytearray()
    seg += struct.pack(">II", 0x1, seg_cmdsize)
    seg += b"__TEXT\0".ljust(16, b"\0")
    seg += struct.pack(">IIII", base, 0x1000, 0, total)
    seg += struct.pack(">ii", 7, 5)
    seg += struct.pack(">II", 1, 0)
    sec = bytearray()
    sec += b"__text\0".ljust(16, b"\0")
    sec += b"__TEXT\0".ljust(16, b"\0")
    sec += struct.pack(">II", text_addr, 4)
    sec += struct.pack(">IIIIIII", text_off, 0, 0, 0, 0x80000400, 0, 0)
    seg += sec
    buf += seg
    buf += struct.pack(">IIIIII", 0x2, 24, symtab_off, 2, strtab_off, len(strtab))
    d = bytearray()
    d += struct.pack(">II", 0xC, dylib_cmdsize)
    d += struct.pack(">IIII", 24, 0, 0, 0)
    d += dylib_name
    buf += d.ljust(dylib_cmdsize, b"\0")
    t = bytearray()
    t += struct.pack(">II", 0x5, thread_cmdsize)
    t += struct.pack(">II", 1, thread_count)
    state = [0] * thread_count
    state[0] = text_addr  # srr0 = PC
    for w in state:
        t += struct.pack(">I", w)
    buf += t
    buf += text
    buf += struct.pack(">IBBhI", 1, 0x0F, 1, 0, text_addr)
    buf += struct.pack(">IBBhI", 7, 0x01, 0, 0, 0)
    buf += strtab
    assert len(buf) == total
    return bytes(buf)


# ---------------------------------------------------------------------------
# Expected values: identical to the MoonBit golden assertions.
# ---------------------------------------------------------------------------
EXPECTED = {
    "macho64le": {
        "magic_bytes": bytes.fromhex("cffaedfe"),
        "magic": 0xFEEDFACF, "class": 64, "cputype": 0x01000007,
        "cpusubtype": 3, "filetype": 2, "ncmds": 4, "sizeofcmds": 256,
        "entry": 0x100000120, "entry_mode": "main",
        "segments": [("__TEXT", 0x100000000, 0x1000, 0, 339, 5, 7, 1)],
        "sections": [("__text", "__TEXT", 0x100000120, 4, 288, 0, 0x80000400)],
        "symbols": [("_main", 0x100000120, 0x0F, 1), ("_printf", 0, 0x01, 0)],
        "libraries": ["/usr/lib/libSystem.B.dylib"],
        "exports": ["_main"],
    },
    "macho32be": {
        "magic_bytes": bytes.fromhex("feedface"),
        "magic": 0xFEEDFACE, "class": 32, "cputype": 18,
        "cpusubtype": 0, "filetype": 2, "ncmds": 4, "sizeofcmds": 380,
        "entry": 0x1198, "entry_mode": "unixthread",
        "segments": [("__TEXT", 0x1000, 0x1000, 0, 451, 5, 7, 1)],
        "sections": [("__text", "__TEXT", 0x1198, 4, 408, 0, 0x80000400)],
        "symbols": [("_main", 0x1198, 0x0F, 1), ("_printf", 0, 0x01, 0)],
        "libraries": ["/usr/lib/libSystem.B.dylib"],
        "exports": ["_main"],
    },
}


def run_moon_test():
    moon = shutil.which("moon") or "moon"
    proc = subprocess.run([moon, "test", "src/macho"], cwd=str(ROOT),
                          capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        print(out)
        raise SystemExit("FAIL: moon test src/macho exited non-zero")
    import re
    m = re.search(r"Total tests: (\d+), passed: (\d+), failed: (\d+)", out)
    if not m or int(m.group(1)) == 0 or m.group(1) != m.group(2) or m.group(3) != "0":
        print(out)
        raise SystemExit("FAIL: test summary missing or tests did not all pass")
    print(f"moon test src/macho: Total tests: {m.group(1)}, passed: {m.group(2)}, failed: 0")
    hexes = {}
    for name in ("macho64le", "macho32be"):
        line = next((l for l in out.splitlines() if l.startswith(f"MACHOCROSS {name} ")), None)
        if line is None:
            raise SystemExit(f"FAIL: no MACHOCROSS {name} line in test output")
        hexes[name] = bytes.fromhex(line.split()[2])
    return hexes


def check_fixture(name, moon_bytes, py_bytes):
    exp = EXPECTED[name]
    print(f"== {name} ==")
    # Byte-identity gate: LIEF parses the exact bytes MoonBit asserted on.
    expect(moon_bytes == py_bytes, "MoonBit dump == independent Python fixture (byte-identical)")
    expect(moon_bytes[:4] == exp["magic_bytes"], "on-disk magic bytes (class + endian)")
    b = lief.parse(moon_bytes)
    expect(b is not None, "lief.parse succeeded")
    if b is None:
        return
    h = b.header
    expect(iv(h.magic) == exp["magic"], f"header magic {hex(exp['magic'])}")
    expect(iv(h.cpu_type) == exp["cputype"], f"cputype {hex(exp['cputype'])}")
    expect(iv(h.cpu_subtype) == exp["cpusubtype"], f"cpusubtype {exp['cpusubtype']}")
    expect(iv(h.file_type) == exp["filetype"], f"filetype {exp['filetype']} (MH_EXECUTE)")
    expect(h.nb_cmds == exp["ncmds"], f"ncmds {exp['ncmds']}")
    expect(h.sizeof_cmds == exp["sizeofcmds"], f"sizeofcmds {exp['sizeofcmds']}")
    # Entry.
    if exp["entry_mode"] == "main":
        expect(iv(b.entrypoint) == exp["entry"], f"LC_MAIN entrypoint {hex(exp['entry'])}")
    else:
        tc = b.thread_command
        expect(tc is not None and tc.flavor == 1, "LC_UNIXTHREAD PPC_THREAD_STATE (flavor 1)")
        if tc is not None:
            srr0 = int.from_bytes(bytes(tc.state)[0:4], "big")
            expect(srr0 == exp["entry"], f"LC_UNIXTHREAD srr0 {hex(exp['entry'])} (from raw state)")
    # Segments.
    segs = list(b.segments)
    expect(len(segs) == len(exp["segments"]), f"segment count {len(exp['segments'])}")
    for s, (nm, va, vs, fo, fs, ip, mp, ns) in zip(segs, exp["segments"]):
        expect(s.name == nm, f"segment name {nm}")
        expect(s.virtual_address == va, f"segment {nm} vmaddr {hex(va)}")
        expect(s.virtual_size == vs, f"segment {nm} vmsize {hex(vs)}")
        expect(s.file_offset == fo, f"segment {nm} fileoff {fo}")
        expect(s.file_size == fs, f"segment {nm} filesize {fs}")
        expect(iv(s.init_protection) == ip, f"segment {nm} initprot {ip}")
        expect(iv(s.max_protection) == mp, f"segment {nm} maxprot {mp}")
        expect(s.numberof_sections == ns, f"segment {nm} nsects {ns}")
    # Sections.
    secs = list(b.sections)
    expect(len(secs) == len(exp["sections"]), f"section count {len(exp['sections'])}")
    for s, (nm, sg, va, sz, off, ty, fl) in zip(secs, exp["sections"]):
        expect(s.name == nm, f"section name {nm}")
        expect(s.segment_name == sg, f"section {nm} segname {sg}")
        expect(s.virtual_address == va, f"section {nm} addr {hex(va)}")
        expect(s.size == sz, f"section {nm} size {sz}")
        expect(s.offset == off, f"section {nm} offset {off}")
        expect(iv(s.type) == ty, f"section {nm} type {ty} (S_REGULAR)")
        expect(iv(s.flags) == fl, f"section {nm} flags {hex(fl)}")
    # Symbols.
    syms = list(b.symbols)
    expect(len(syms) == len(exp["symbols"]), f"symbol count {len(exp['symbols'])}")
    for s, (nm, val, rt, ns) in zip(syms, exp["symbols"]):
        expect(s.name == nm, f"symbol name {nm}")
        expect(iv(s.value) == val, f"symbol {nm} value {hex(val)}")
        expect(iv(s.raw_type) == rt, f"symbol {nm} n_type {hex(rt)}")
        expect(s.numberof_sections == ns, f"symbol {nm} n_sect {ns}")
    # Derived exports: defined, non-stab symbols.
    exports = [s.name for s in syms
               if (iv(s.raw_type) & 0xE0) == 0 and (iv(s.raw_type) & 0x0E) != 0 and s.name]
    expect(exports == exp["exports"], f"defined-symbol exports {exp['exports']}")
    # Dylibs.
    libs = [l.name for l in b.libraries]
    expect(libs == exp["libraries"], f"dylib imports {exp['libraries']}")


def main():
    hexes = run_moon_test()
    builders = {"macho64le": build_macho64le, "macho32be": build_macho32be}
    for name in ("macho64le", "macho32be"):
        check_fixture(name, hexes[name], builders[name]())
    print()
    if FAILED != 0:
        raise SystemExit(f"FAIL: {FAILED} of {CHECKS} cross-checks mismatched")
    print(f"PASS: all {CHECKS} LIEF cross-checks agree with the MoonBit golden tests")
    print("CROSSCHECK PASS")


if __name__ == "__main__":
    main()