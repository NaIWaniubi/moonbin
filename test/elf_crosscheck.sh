#!/usr/bin/env bash
# Cross-check the crafted ELF fixtures against GNU readelf.
#
# The MoonBit tests in src/elf/elf_test.mbt build two deterministic ELF files
# (ELF64 little-endian x86-64, ELF32 big-endian PowerPC) and print their exact
# bytes as hex lines tagged "ELFCROSS". This script runs the test suite,
# decodes those lines into a temp dir, and verifies that `readelf -h -S -s`
# (plus `-d` for DT_NEEDED) reports the same header fields, section names and
# symbol names/values that the golden tests assert. No host execution of the
# fixtures happens: readelf only reads them.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v readelf >/dev/null 2>&1; then
  echo "FAIL: readelf is not on PATH" >&2
  exit 1
fi
PY=""
for cand in python python3; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  echo "FAIL: python is not on PATH (needed to decode hex)" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== running moon test src/elf =="
if ! moon test src/elf >"$TMP/test_output.txt" 2>&1; then
  cat "$TMP/test_output.txt"
  echo "FAIL: moon test src/elf failed" >&2
  exit 1
fi
if ! grep -Eq 'Total tests: [1-9][0-9]*, passed: [1-9][0-9]*, failed: 0' "$TMP/test_output.txt"; then
  cat "$TMP/test_output.txt"
  echo "FAIL: test summary missing or tests did not all pass" >&2
  exit 1
fi
grep -E 'Total tests:' "$TMP/test_output.txt"

# Decode the exact bytes the tests asserted on.
for name in elf64le elf32be; do
  hex="$(grep "^ELFCROSS $name " "$TMP/test_output.txt" | head -1 | awk '{print $3}')"
  if [ -z "$hex" ]; then
    echo "FAIL: no ELFCROSS $name line in test output" >&2
    exit 1
  fi
  "$PY" -I -c 'import sys, binascii; open(sys.argv[1], "wb").write(binascii.unhexlify(sys.argv[2].strip()))' \
    "$TMP/$name.elf" "$hex"
done

CHECKS=0
FAILED=0
expect() { # expect <file> <extended-regex> <label>
  CHECKS=$((CHECKS + 1))
  if grep -Eq "$2" "$1"; then
    echo "  ok: $3"
  else
    echo "  MISSING: $3  (pattern: $2)" >&2
    FAILED=$((FAILED + 1))
  fi
}

for name in elf64le elf32be; do
  echo "== readelf -h -S -s $name =="
  if ! readelf -h -S -s "$TMP/$name.elf" >"$TMP/$name.readelf.txt" 2>&1; then
    cat "$TMP/$name.readelf.txt"
    echo "FAIL: readelf exited non-zero on $name" >&2
    exit 1
  fi
  if grep -Eq 'readelf: (Error|Warning)' "$TMP/$name.readelf.txt"; then
    cat "$TMP/$name.readelf.txt"
    echo "FAIL: readelf reported errors/warnings on $name" >&2
    exit 1
  fi
done

R64="$TMP/elf64le.readelf.txt"
R32="$TMP/elf32be.readelf.txt"

echo "== ELF64 little-endian header =="
expect "$R64" 'Class:[[:space:]]*ELF64' "class ELF64"
expect "$R64" 'Data:.*little endian' "little endian"
expect "$R64" 'Machine:.*X86-64' "machine x86-64"
expect "$R64" 'Entry point address:[[:space:]]*0x401000' "entry 0x401000"
expect "$R64" 'Number of program headers:[[:space:]]*2' "2 program headers"
expect "$R64" 'Number of section headers:[[:space:]]*8' "8 section headers"
expect "$R64" 'Section header string table index:[[:space:]]*7' "shstrndx 7"

echo "== ELF64 section names =="
expect "$R64" '\.text[[:space:]]+PROGBITS[[:space:]]+0000000000401000[[:space:]]+000000b0' ".text PROGBITS @0xb0 addr 0x401000"
expect "$R64" '\.symtab[[:space:]]+SYMTAB' ".symtab SYMTAB"
expect "$R64" '\.strtab[[:space:]]+STRTAB' ".strtab STRTAB"
expect "$R64" '\.dynsym[[:space:]]+DYNSYM' ".dynsym DYNSYM"
expect "$R64" '\.dynstr[[:space:]]+STRTAB' ".dynstr STRTAB"
expect "$R64" '\.dynamic[[:space:]]+DYNAMIC' ".dynamic DYNAMIC"
expect "$R64" '\.shstrtab[[:space:]]+STRTAB' ".shstrtab STRTAB"

echo "== ELF64 symbols =="
expect "$R64" '0000000000401000[[:space:]]+4 FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+1[[:space:]]+main' "main FUNC GLOBAL value 0x401000 size 4 ndx 1"
expect "$R64" '0000000000401004[[:space:]]+8 OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+1[[:space:]]+helper' "helper OBJECT GLOBAL value 0x401004 size 8 ndx 1"
expect "$R64" 'FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+UND[[:space:]]+printf' "printf FUNC GLOBAL undefined"
expect "$R64" '0000000000402000[[:space:]]+4 OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+1[[:space:]]+moonbin_version' "moonbin_version OBJECT GLOBAL value 0x402000 size 4 ndx 1"

echo "== ELF32 big-endian header =="
expect "$R32" 'Class:[[:space:]]*ELF32' "class ELF32"
expect "$R32" 'Data:.*big endian' "big endian"
expect "$R32" 'Machine:.*PowerPC' "machine PowerPC"
expect "$R32" 'Entry point address:[[:space:]]*0x1001000' "entry 0x1001000"
expect "$R32" 'Number of program headers:[[:space:]]*2' "2 program headers"
expect "$R32" 'Number of section headers:[[:space:]]*8' "8 section headers"
expect "$R32" 'Section header string table index:[[:space:]]*7' "shstrndx 7"

echo "== ELF32 section names =="
expect "$R32" '\.text[[:space:]]+PROGBITS[[:space:]]+01001000[[:space:]]+000074' ".text PROGBITS @0x74 addr 0x1001000"
expect "$R32" '\.symtab[[:space:]]+SYMTAB' ".symtab SYMTAB"
expect "$R32" '\.strtab[[:space:]]+STRTAB' ".strtab STRTAB"
expect "$R32" '\.dynsym[[:space:]]+DYNSYM' ".dynsym DYNSYM"
expect "$R32" '\.dynstr[[:space:]]+STRTAB' ".dynstr STRTAB"
expect "$R32" '\.dynamic[[:space:]]+DYNAMIC' ".dynamic DYNAMIC"
expect "$R32" '\.shstrtab[[:space:]]+STRTAB' ".shstrtab STRTAB"

echo "== ELF32 symbols =="
expect "$R32" '01001000[[:space:]]+4 FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+1[[:space:]]+main' "main FUNC GLOBAL value 0x1001000 size 4 ndx 1"
expect "$R32" '01001004[[:space:]]+8 OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+1[[:space:]]+helper' "helper OBJECT GLOBAL value 0x1001004 size 8 ndx 1"
expect "$R32" 'FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+UND[[:space:]]+printf' "printf FUNC GLOBAL undefined"
expect "$R32" '01002000[[:space:]]+4 OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+1[[:space:]]+moonbin_version' "moonbin_version OBJECT GLOBAL value 0x1002000 size 4 ndx 1"

echo "== DT_NEEDED (readelf -d) =="
for name in elf64le elf32be; do
  readelf -d "$TMP/$name.elf" >"$TMP/$name.dynamic.txt" 2>&1
  expect "$TMP/$name.dynamic.txt" 'Shared library: \[libc\.so\.6\]' "$name DT_NEEDED libc.so.6"
done

echo
if [ "$FAILED" -ne 0 ]; then
  echo "FAIL: $FAILED of $CHECKS cross-checks missing" >&2
  exit 1
fi
echo "PASS: all $CHECKS readelf cross-checks agree with the MoonBit golden tests"