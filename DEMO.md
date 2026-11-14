# Demo walkthrough

A 3-minute story that shows why moonbin matters, using only the shipped CLI and
the in-browser workbench. Every claim below is backed by a cross-check in `test/`.

## 1. One codebase, two worlds (the MoonBit story)

```bash
moon build --target native --release cmd/main   # native binary
moon build --target wasm  --release src/web     # browser module
bash web/build.sh && (cd web && python -m http.server 8080)
```

Open http://127.0.0.1:8080, drop `examples/notepad.exe`. The *same* MoonBit code
that produced the native binary now parses, disassembles, and maps source lines
**inside the browser**, with a live `ms · MB/s` badge. No FFI, no server, no
dependencies. This is the multi-backend advantage MoonBit is designed for.

## 2. Rigor you can audit

```bash
moonbin info      examples/notepad.exe     # 315 imports, 7 sections
moonbin callgraph examples/notepad.exe     # 1227 direct-call edges
moonbin dwarf     examples/dbg.exe         # addr -> dbg.c:line, add/main ranges
```

Each of these is verified against an independent oracle:
`objdump` (structure + callgraph + DWARF), `readelf` (ELF), `lief` (Mach-O),
`capstone` (disassembly). Run `test/*_crosscheck.*` to reproduce. A parser that
refuses malformed input instead of guessing, and a disassembler that reports
`.byte` rather than silently truncating, is a tool you can trust in a pipeline.

## 3. Native-class speed, memory-safe

`python -I test/bench.py` → moonbin ≈ objdump (C), within ~1.3× of capstone (C),
while being bounds-checked pure MoonBit. See BENCHMARKS.md.

## The pitch

> moonbin is a complete, zero-FFI reverse-engineering platform in MoonBit —
> PE/ELF/Mach-O parsing, x86-64 disassembly, CFG/call-graph, DWARF source mapping,
> strings/entropy — verified byte-for-byte against the industry's reference tools,
> at native-class speed, and running unchanged in your browser.