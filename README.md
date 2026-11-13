# moonbin

**Pure-MoonBit binary format parsing and x86-64 disassembly.** Read real PE / ELF
executables, walk their sections / symbols / imports / exports, and disassemble
`.text` — with zero FFI, from the same MoonBit source compiled to native, wasm and js.

Mature analogs in other ecosystems: `goblin` / `LIEF` / `pefile` (format parsing),
`capstone` / `iced-x86` (disassembly). MoonBit had no equivalent; moonbin fills that gap.

```
$ moonbin info notepad.exe
format   PE
machine  34404
entry    0x19a0
base     0x140000000
sections 7  symbols 0  imports 315  exports 0

$ moonbin disasm kernel32.dll --count 4
0x1000:  int3
0x1001:  int3
0x1002:  int3
0x1003:  int3
```

## Why it is trustworthy

A parser that silently guesses is worse than one that refuses. Every read is
bounds-checked; malformed input returns `Truncated` / `BadMagic` / `Invalid`,
never a panic and never a fabricated field. The disassembler reports opcodes
outside its supported subset as a raw `.byte` row and keeps going, instead of
silently truncating the dump.

Correctness is pinned against the reference tools, not asserted:

- **PE** — golden fixtures cross-checked with `objdump -x` (14/14), plus a real
  `notepad.exe`: entry, image base, all 7 sections and all 315 imports (including
  ordinal imports) match objdump exactly.
- **ELF** — ELF64-LE and ELF32-BE fixtures cross-checked with `readelf -h -S -s -d`
  (38/38 field/name/value matches).
- **x86-64** — 199/199 mnemonic+length agreement with **capstone** on a fixed blob
  and real `.text`; on 400-instruction windows of `kernel32.dll` / `notepad.exe`
  the supported subset agrees 100% (119/119, 147/147), with x87 bytes honestly
  refused as `.byte`.

## Quickstart

```bash
# MoonBit toolchain required
moon check --deny-warn        # 0 errors, 0 warnings
moon test                     # 62 tests
moon build --target native --release cmd/main
bin=_build/native/release/build/cmd/main/main.exe

$bin info     <file>          # format / machine / entry / base / counts
$bin sections <file>          # name offset size vaddr flags
$bin symbols  <file>
$bin imports  <file>
$bin exports  <file>
$bin disasm   <file> [--count N]
# add --json to any command for machine-readable output

# reference-tool cross-checks (need objdump / readelf / python+capstone)
bash test/pe_crosscheck.sh
bash test/elf_crosscheck.sh
python -I test/disasm_crosscheck.py verify
```

The same source builds to wasm: `moon build --target wasm --release cmd/main`.

## Architecture

| package | role |
|---|---|
| `src/core` | bounds-checked `Reader` + format-agnostic `Region/Symbol/Import/Export` |
| `src/pe` | PE32 / PE32+ : DOS→NT→COFF→optional→sections→import/export/symbols |
| `src/elf` | ELF32/64, both endians: headers, segments, symtab/dynsym, dynamic |
| `src/disasm` | x86-64: prefixes, REX, ModR/M+SIB, disp/imm, common integer+SSE subset |
| `src/format` | magic-based container detection |
| `cmd/main` | CLI: info/sections/symbols/imports/exports/disasm, `--json` |

## Supported / not supported (honest boundaries)

- PE32 & PE32+; ELF32 & ELF64, little & big endian. Mach-O detected but refused (v0.1).
- x86-64 common integer + basic SSE subset. AVX/VEX/EVEX, x87, MMX, far transfers
  return `Invalid` (single `decode`) or `.byte` (streaming `disassemble`).
- ELF imports are per-`DT_NEEDED` library (no per-symbol attribution — that would
  require guessing). PE delay-imports not parsed.
- No dynamic loading, no unpacking, no emulation. This is a static reader.

## License

Apache-2.0. Dependencies: `moonbitlang/x` (Apache-2.0), unmodified public API only.