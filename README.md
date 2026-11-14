# moonbin

**Pure-MoonBit binary format parsing and x86-64 reverse-engineering.** Read real
PE / ELF / Mach-O executables, walk their sections / symbols / imports / exports,
disassemble `.text` (integer + SSE + x87 + VEX/AVX subset), build basic-block CFGs
and direct call graphs, map addresses back to source lines via DWARF (v4/v5), and
run strings / entropy analysis — with zero FFI, from the same MoonBit source
compiled to native, wasm and js, plus an in-browser RE workbench (hex + CFG +
entropy bars).

Mature analogs in other ecosystems: `goblin` / `LIEF` / `pefile` (format parsing),
`capstone` / `iced-x86` (disassembly). MoonBit had no equivalent; moonbin fills that gap.

```
$ moonbin info notepad.exe
format   PE
machine  34404
entry    0x19a0
base     0x140000000
sections 7  symbols 0  imports 315  exports 0

$ moonbin entropy kernel32.dll
entropy 6.3952274 / 8.0
```

## Why it is trustworthy

A parser that silently guesses is worse than one that refuses. Every read is
bounds-checked; malformed input returns `Truncated` / `BadMagic` / `Invalid`,
never a panic and never a fabricated field. Core headers / imports / exports are
strict; *optional* PE directories (relocs / delay-import / TLS / resources) are
best-effort so a real DLL with an in-memory-only optional RVA still parses. The
disassembler reports opcodes outside its subset as a raw `.byte` row and keeps
going, instead of silently truncating the dump.

Correctness is pinned against reference tools, not asserted:

- **PE** — golden fixtures vs `objdump -x` (14/14) + real `notepad.exe`: entry, base,
  7 sections, all 315 imports (incl. ordinals) match exactly.
- **ELF** — ELF64-LE / ELF32-BE fixtures vs `readelf -h -S -s -d` (38/38).
- **Mach-O** — Mach-O64-LE / Mach-O32-BE fixtures vs `lief` (77/77).
- **x86-64** — 199/199 mnemonic+length vs **capstone** on a fixed blob; on 400-insn
  windows of real `kernel32.dll` / `notepad.exe` the supported subset agrees 100%
  with only ~1 `.byte` refusal (x87 now decoded).
- **call graph** — 1227/1227 direct-call edges on real `notepad.exe` agree with
  `objdump -d`.
- **DWARF** — line rows and subprogram ranges on a real gcc `-g` binary (v4 & v5)
  equal `objdump --dwarf=decodedline` / info.
- **fuzz** — 1424 deterministic mutations across all parsers: no panic.

## Quickstart

```bash
moon check --deny-warn        # 0 errors, 0 warnings
moon test                     # 181 tests
moon build --target native --release cmd/main
bin=_build/native/release/build/cmd/main/main.exe

$bin info     <file>
$bin sections <file>
$bin symbols  <file>
$bin imports  <file>
$bin exports  <file>
$bin disasm   <file> [--count N]
$bin cfg      <file>          # basic blocks + successors
$bin callgraph <file>         # direct call edges
$bin dwarf    <file>          # DWARF source lines + subprogram ranges
$bin strings  <file>          # ASCII runs >= 4
$bin entropy  <file>          # Shannon entropy 0..8
# add --json to any command

# reference-tool cross-checks (objdump / readelf / lief / capstone)
bash test/pe_crosscheck.sh
bash test/elf_crosscheck.sh
python -I test/macho_crosscheck.py
python -I test/disasm_crosscheck.py verify
python -I test/analysis_crosscheck.py
node test/web_e2e.mjs         # wasm RE workbench smoke (+ DOM leg when Chrome present)

# browser playground
bash web/build.sh && (cd web && python -m http.server 8080)
```

The same source builds to wasm: `moon build --target wasm --release cmd/main`.

## Architecture

| package | role |
|---|---|
| `src/core` | bounds-checked `Reader` + format-agnostic `Region/Symbol/Import/Export` |
| `src/pe` | PE32/PE32+ : headers, sections, import/export/symbols, relocs/delay/TLS/resources |
| `src/elf` | ELF32/64 both endians: headers, segments, symtab/dynsym, dynamic, rela imports |
| `src/macho` | Mach-O 32/64 both endians: segments/sections, symtab, dylibs, entry |
| `src/disasm` | x86-64: prefixes/REX/ModR/M/SIB, integer+SSE+x87+VEX/AVX subset |
| `src/analysis` | basic-block CFG + direct call graph over the decoded stream |
| `src/dwarf` | DWARF v4/v5 line table + subprogram source mapping |
| `src/inspect` | strings / Shannon entropy |
| `src/format` | magic-based container detection |
| `src/web` + `web/` | single-file wasm playground |
| `cmd/main` | CLI: info/sections/symbols/imports/exports/disasm/strings/entropy, `--json` |

## Supported / not supported (honest boundaries)

- PE32 & PE32+; ELF32 & ELF64; Mach-O 32 & 64; little & big endian where applicable.
- x86-64 common integer + SSE + x87 FPU + VEX/AVX (map 1) subset. AVX2/AVX-512
  (VEX map 2/3, EVEX), MMX, far transfers return `Invalid` / `.byte`.
- ELF imports: per-`DT_NEEDED` plus per-symbol rela (JUMP_SLOT/GLOB_DAT) attribution.
- No dynamic loading, no unpacking, no emulation. This is a static reader.

## License

Apache-2.0. Dependencies: `moonbitlang/x` (Apache-2.0), unmodified public API only.