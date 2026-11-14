# Benchmarks

Honest, reproducible wall-clock numbers. Method: best of 3 runs, `--release`
native build, Windows x64, on `examples/notepad.exe` (360 KB, `.text` = 160 KB,
43 821 instructions). moonbin and objdump times include container parsing;
capstone is given the raw `.text` bytes with `skipdata=True` so it covers the
same instruction count (it otherwise stops at the first undecodable byte).

| tool | language | full `.text` disassembly | notes |
|---|---|---|---|
| **moonbin** | pure MoonBit (native) | **~404 ms** | zero FFI, bounds-checked, `.byte` continuation |
| objdump `-d` | C (BFD) | ~424 ms | whole-file disassembly |
| capstone (skipdata) | C | ~305 ms | raw `.text`, 43 821 insns |

Takeaway: a memory-safe, zero-FFI MoonBit implementation lands **on par with
objdump and within ~1.3× of capstone (C)** — and the *same source* compiles to
wasm and runs in the browser (the workbench reports its own in-browser ms / MB/s).

Reproduce:

```bash
moon build --target native --release cmd/main
python -I test/bench.py            # prints the three timings
```

The point is not "fastest disassembler". It is that one safe MoonBit codebase
delivers native-class throughput *and* a zero-dependency browser build — the
multi-backend story MoonBit is designed for.