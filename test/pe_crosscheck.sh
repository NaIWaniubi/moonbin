#!/usr/bin/env bash
# Cross-check the moonbin PE golden fixture against an independent parser
# (GNU objdump -x). The fixture bytes below mirror build_pe(true) in
# src/pe/pe_test.mbt byte-for-byte; the MoonBit tests assert our parser
# returns exactly these constants, and this script asserts objdump sees the
# same facts in the same bytes.
#
# Usage:
#   test/pe_crosscheck.sh
# Optional deeper checks (env vars):
#   PE_HARNESS=/path/to/peharness   run the moonbin parser on the fixture and
#                                   diff its normalized output against the
#                                   objdump-verified constants
#   PE_NOTEPAD=/path/to/real.exe    with PE_HARNESS set, also cross-check a
#                                   real PE (headers, sections, full import
#                                   list incl. ordinals) against objdump
set -euo pipefail

PY="$(command -v python || command -v python3)"
command -v objdump >/dev/null 2>&1 || { echo "objdump not found on PATH" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- build the golden PE32+ fixture (same layout as pe_test.mbt) ---
"$PY" -I - "$TMP/golden.exe" <<'PYEOF'
import struct, sys
a = bytearray(0x600)
def p16(o, v): struct.pack_into('<H', a, o, v)
def p32(o, v): struct.pack_into('<I', a, o, v)
def p64(o, v): struct.pack_into('<Q', a, o, v)
def ps(o, s): a[o:o+len(s)] = s.encode('ascii')
# DOS header
ps(0, 'MZ'); p32(0x3C, 0x40)
# NT signature + COFF
ps(0x40, 'PE'); p16(0x44, 0x8664); p16(0x46, 2)
p32(0x48, 0x60000000); p16(0x54, 240); p16(0x56, 0x2022)
# Optional header (PE32+)
o = 0x58
p16(o, 0x20B); a[o+2] = 14
p32(o+4, 0x200); p32(o+8, 0x200)
p32(o+16, 0x1000); p32(o+20, 0x1000)
p64(o+24, 0x140000000)
p32(o+32, 0x1000); p32(o+36, 0x200)
p16(o+40, 6); p16(o+48, 6)
p32(o+56, 0x3000); p32(o+60, 0x200)
p16(o+68, 3); p16(o+70, 0x160)
p64(o+72, 0x100000); p64(o+80, 0x1000)
p64(o+88, 0x100000); p64(o+96, 0x1000)
p32(o+108, 16)
d = o + 112
p32(d, 0x2000); p32(d+4, 0xA0)      # export directory
p32(d+8, 0x2100); p32(d+12, 40)     # import directory
# Section table
s = o + 240
a[s:s+8] = b'.text'.ljust(8, b'\0')
p32(s+8, 0x40); p32(s+12, 0x1000); p32(s+16, 0x200); p32(s+20, 0x200)
p32(s+36, 0x60000020)
s2 = s + 40
a[s2:s2+8] = b'.rdata'.ljust(8, b'\0')
p32(s2+8, 0x1C0); p32(s2+12, 0x2000); p32(s2+16, 0x200); p32(s2+20, 0x400)
p32(s2+36, 0x40000040)
# .text raw
for i in range(0x200, 0x400): a[i] = 0xCC
a[0x200] = 0xC3
# .rdata raw: export directory
rd = 0x400
p32(rd+4, 0x60000000)
p32(rd+12, 0x2080); p32(rd+16, 1); p32(rd+20, 1); p32(rd+24, 1)
p32(rd+28, 0x2040); p32(rd+32, 0x2050); p32(rd+36, 0x2060)
p32(rd+0x40, 0x1000); p32(rd+0x50, 0x2090); p16(rd+0x60, 0)
ps(rd+0x80, 'moonbin_test.dll'); ps(rd+0x90, 'moonbin_export')
# import directory + thunks
im = rd + 0x100
p32(im, 0x2140); p32(im+12, 0x2180); p32(im+16, 0x2160)
ilt, iat = rd+0x140, rd+0x160
p64(ilt, 0x21A0); p64(ilt+8, 0x21B0)
p64(iat, 0x21A0); p64(iat+8, 0x21B0)
ps(rd+0x180, 'KERNEL32.dll')
p16(rd+0x1A0, 0); ps(rd+0x1A2, 'LoadLibraryA')
p16(rd+0x1B0, 0); ps(rd+0x1B2, 'GetProcAddress')
assert len(a) == 0x600
with open(sys.argv[1], 'wb') as f:
    f.write(bytes(a))
print('fixture: %s (1536 bytes)' % sys.argv[1])
PYEOF

OBJ="$TMP/objdump.txt"
objdump -x "$TMP/golden.exe" > "$OBJ" 2>&1

fail=0
expect() {
  local label="$1"; shift
  if grep "$@" "$OBJ" >/dev/null 2>&1; then
    echo "OK   objdump: $label"
  else
    echo "FAIL objdump: $label" >&2
    fail=1
  fi
}

expect "file format pei-x86-64"        -E "file format pei-x86-64"
expect "Magic PE32+ (020b)"            -E "Magic[[:space:]]+020b"
expect "entry RVA 0x1000"              -E "AddressOfEntryPoint[[:space:]]+0*1000$"
expect "image base 0x140000000"        -E "ImageBase[[:space:]]+0*140000000$"
expect "start address base+entry"      -E "start address 0x0*140001000"
expect "section .text present"         -E "^[[:space:]]*[0-9]+ \.text[[:space:]]"
expect "section .rdata present"        -E "^[[:space:]]*[0-9]+ \.rdata[[:space:]]"
expect ".text file offset 0x200"       -E "\.text[[:space:]]+[0-9a-f]+[[:space:]]+[0-9a-f]+[[:space:]]+[0-9a-f]+[[:space:]]+0*200[[:space:]]"
expect ".rdata file offset 0x400"      -E "\.rdata[[:space:]]+[0-9a-f]+[[:space:]]+[0-9a-f]+[[:space:]]+[0-9a-f]+[[:space:]]+0*400[[:space:]]"
expect "import DLL KERNEL32.dll"       -F "DLL Name: KERNEL32.dll"
expect "import LoadLibraryA"           -E "[0-9a-f]+[[:space:]]+[0-9]+[[:space:]]+LoadLibraryA$"
expect "import GetProcAddress"         -E "[0-9a-f]+[[:space:]]+[0-9]+[[:space:]]+GetProcAddress$"
expect "export name moonbin_export"    -E "^[[:space:]]*\[[[:space:]]*0\][[:space:]]+moonbin_export"
expect "export ordinal 1, RVA 0x1000"  -E "\[[[:space:]]*0\][[:space:]]+\+base\[[[:space:]]*1\][[:space:]]+1000 Export RVA"

# --- optional: run the moonbin parser itself on the same bytes ---
if [ -n "${PE_HARNESS:-}" ]; then
  # native Windows harness prints CRLF; normalize for the diff
  "$PE_HARNESS" "$TMP/golden.exe" | tr -d '\r' > "$TMP/parser.txt"
  cat > "$TMP/expected.txt" <<'EXPEOF'
machine 34404
is64 true
entry 4096
image_base 5368709120
section .text rx 512 512 4096
section .rdata r 1024 512 8192
import KERNEL32.dll LoadLibraryA
import KERNEL32.dll GetProcAddress
export moonbin_export 1 4096
EXPEOF
  if diff -u "$TMP/expected.txt" "$TMP/parser.txt"; then
    echo "OK   moonbin parser == objdump-verified constants (fixture)"
  else
    echo "FAIL moonbin parser output differs on fixture" >&2
    fail=1
  fi

  # --- optional: real PE cross-check (headers/sections/imports) ---
  if [ -n "${PE_NOTEPAD:-}" ] && [ -f "${PE_NOTEPAD}" ]; then
    "$PE_HARNESS" "$PE_NOTEPAD" | tr -d '\r' > "$TMP/real_parser.txt"
    objdump -x "$PE_NOTEPAD" > "$TMP/real_objdump.txt" 2>&1
    if "$PY" -I - "$TMP/real_objdump.txt" "$TMP/real_parser.txt" <<'CMPEOF'
import re, sys
obj = open(sys.argv[1], encoding='utf-8', errors='replace').read()
par = open(sys.argv[2], encoding='utf-8').read().splitlines()
fails = []
def check(name, a, b):
    if a == b:
        print('OK   real PE: %s (%s)' % (name, len(a) if isinstance(a, list) else a))
    else:
        fails.append(name)
        print('FAIL real PE: %s' % name)
        if isinstance(a, list):
            sa, sb = set(map(tuple, a)), set(map(tuple, b))
            print('  only objdump:', sorted(sa - sb)[:8])
            print('  only parser :', sorted(sb - sa)[:8])
entry_obj = int(re.search(r'AddressOfEntryPoint\s+([0-9a-f]+)', obj).group(1), 16)
base_obj = int(re.search(r'ImageBase\s+([0-9a-f]+)', obj).group(1), 16)
p = {}
for l in par:
    t = l.split(' ', 1)
    if t[0] in ('machine', 'is64', 'entry', 'image_base'):
        p[t[0]] = t[1]
check('entry RVA', entry_obj, int(p['entry']))
check('image_base', base_obj, int(p['image_base']))
start_obj = int(re.search(r'start address 0x([0-9a-f]+)', obj).group(1), 16)
check('start address = base+entry', start_obj, base_obj + entry_obj)
# sections: objdump Size is VirtualSize; Region.size is SizeOfRawData,
# which must equal align(VirtualSize, FileAlignment) for these images.
sec_obj, in_secs = [], False
for line in obj.splitlines():
    if line.startswith('Sections:'):
        in_secs = True
        continue
    if not in_secs or line.startswith('Idx Name'):
        continue
    m = re.match(r'\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
    if m:
        name, size, vma, lma, off = m.groups()
        sec_obj.append((name, int(size, 16), int(vma, 16) - base_obj, int(off, 16)))
    elif sec_obj and line.strip() and not line.startswith(' '):
        break
sec_par = []
for l in par:
    if l.startswith('section '):
        _, name, flags, off, size, vaddr = l.split(' ')
        sec_par.append((name, int(size), int(vaddr), int(off)))
fa = int(re.search(r'FileAlignment\s+([0-9a-f]+)', obj).group(1), 16)
check('sections (name,rva,offset)', [(n, v, o) for n, s, v, o in sec_obj],
      [(n, v, o) for n, s, v, o in sec_par])
check('sections raw size = align(VirtualSize,FileAlignment)',
      [(n, (s + fa - 1) // fa * fa, v, o) for n, s, v, o in sec_obj], sec_par)
# imports: member lines have 3 fields, descriptor lines have 5
imp_obj, cur_dll, in_imp = [], None, False
for line in obj.splitlines():
    if 'The Import Tables' in line:
        in_imp = True
        continue
    if in_imp and ('The Delay Import Tables' in line or line.startswith('The Export')):
        break
    if not in_imp:
        continue
    m = re.search(r'DLL Name:\s+(\S+)', line)
    if m:
        cur_dll = m.group(1)
        continue
    f = line.split()
    if len(f) == 3 and cur_dll and re.fullmatch(r'[0-9a-f]+', f[0]) and re.fullmatch(r'[0-9a-f]+', f[1]):
        v = int(f[0], 16)
        if v & (1 << 63):
            imp_obj.append((cur_dll, '#%d' % (v & 0xFFFF)))
        elif f[2] != '<none>' and v != 0:
            imp_obj.append((cur_dll, f[2]))
imp_par = [tuple(l.split(' ', 2)[1:]) for l in par if l.startswith('import ')]
check('imports ordered (dll,name)', imp_obj, imp_par)
sys.exit(1 if fails else 0)
CMPEOF
    then
      echo "OK   real PE cross-check passed: $PE_NOTEPAD"
    else
      echo "FAIL real PE cross-check: $PE_NOTEPAD" >&2
      fail=1
    fi
  fi
fi

if [ "$fail" -eq 0 ]; then
  echo "PE CROSS-CHECK PASSED"
else
  echo "PE CROSS-CHECK FAILED" >&2
  exit 1
fi