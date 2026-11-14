# Design & boundaries

This document explains why moonbin is built the way it is, and where it stops.
README shows usage; here we show why the answers can be trusted.

## 1. One reader, every format

All parsing goes through `core.Reader`, a bounds-checked cursor over immutable
`Bytes`. Every accessor returns `Option`/`Result`; end-of-buffer is `None`, which
the format layers turn into `ParseError.Truncated`. There is no unchecked index
anywhere in the parse path. A malformed file therefore produces a *refusal*, not
a crash and not a plausible-looking wrong value. This is the single most important
property: a binary parser will be fed hostile input, and its failure mode must be
"say no", not "make something up".

Multi-byte integers are read as `Int64` so that a `u32` field (max 4294967295)
never overflows the host `Int` (32-bit). Offsets and sizes are validated in
`Int64` before being narrowed, and negative/wrapped values are rejected.

## 2. Formats are independent, the contract is frozen

`pe`, `elf`, `disasm` depend only on `core` and on nothing else. Their public
surface (`parse(Bytes) -> Result[_, ParseError]`, `decode/disassemble`) was frozen
in `INTERFACES.md` before implementation, so the three could be built in parallel
by separate workers in isolated git worktrees and merged without conflict. The
shared vocabulary (`Region/Symbol/Import/Export`) lives in `core` so the CLI can
treat PE and ELF uniformly.

## 3. Disassembly: exact lengths, honest refusals

The decoder tracks prefixes, REX, ModR/M, SIB, displacement and immediate sizes
so that `len` is always the exact encoded length. Unknown opcodes are `Invalid`,
never a guessed instruction.

Two real bugs were caught by cross-checking against capstone on **real** binaries
(not just crafted fixtures), and both are fixed with regression tests:

1. **Shared-cursor relative targets.** `disassemble` uses one `Reader` over the
   whole buffer. The branch-target formula originally added the instruction's
   absolute address to the reader's *global* position, double-counting the bytes
   before the instruction. On `kernel32.dll` this turned `jno -8` at 0x1008 into
   `0x100a` instead of `0x1002`. Fix: record the cursor position at instruction
   start (`Dec.start`) and compute targets relative to it. Caught only because we
   disassembled a real DLL, not a hand-picked blob.

2. **Silent truncation.** `disassemble` originally stopped at the first unsupported
   opcode, so a real `.text` containing x87 produced a misleadingly short dump.
   Fix: emit the undecodable byte as a `.byte` row and continue; only a genuine
   `Truncated` (buffer ended mid-instruction) stops the stream. The dump now shows
   exactly where the supported subset ends instead of hiding it.

## 4. Verification is external, not self-reported

Each package ships a cross-check that regenerates its golden fixture, writes it to
a temp file, and diffs our output against an independent reference tool:
`objdump` (PE), `readelf` (ELF), `capstone` (x86-64). The MoonBit tests assert the
same constants the reference tool reports, so the two legs are transitive: if the
decoder drifts, either leg fails. We additionally ran 400-instruction windows of
real `kernel32.dll` / `notepad.exe`: supported-subset agreement 100%, with x87
bytes refused as `.byte`.

## 5. What we do not do

- No Mach-O parsing (detected, refused), no delay-imports, no per-symbol ELF import
  attribution, no AVX/x87/MMX, no emulation/unpacking. Each is an explicit refusal
  or a documented gap, not a silent approximation.
- `op_str` is our own rendering; cross-checks compare mnemonic + length, not operand
  text, so operand formatting differences are not counted as errors.

Every "no" above corresponds to a concrete `Err`/`.byte` branch in the code.

## 6. v0.2 upgrades and the decisions behind them

- **Mach-O** completes the big three containers (PE/ELF/Mach-O), 32/64 and both
  endians, cross-checked against LIEF (77/77).
- **x87 + VEX/AVX** were added to the disassembler. The x87 tables and the VEX
  decoder are generated/validated against capstone 5 so mnemonic+length agree
  exactly; on real `kernel32.dll` the `.byte` refusal count over a 400-insn window
  dropped from dozens to ~1. Two of the slice's own unit tests were found to
  contradict capstone (wrong VEX pp / REX.B bytes) and were corrected to capstone
  truth rather than bending the decoder.
- **Optional PE directories are best-effort.** The first v0.2 PE revision treated a
  malformed/unmapped reloc/delay/TLS/resource table as fatal, which refused real
  `kernel32.dll` (its optional RVAs are valid in memory but absent from the raw
  file). Core headers/imports/exports remain strict; the four optional parsers now
  fall back to an empty field on error. The corresponding tests assert best-effort
  (Ok + empty), documenting the deliberate strictness split.
- **strings / entropy** (`src/inspect`) and a **wasm playground** (`src/web`, `web/`)
  expose the library in the browser; `test/web_e2e.mjs` verifies the wasm logic in
  node and, when a working headless Chrome is present, the rendered DOM.
- **fuzz** (`cmd/main/fuzz_test.mbt`): 1424 deterministic mutations across every
  parser and the disassembler; a green run is evidence of the no-panic contract.

## 7. v0.3: from parser to analysis platform

- **CFG + call graph** (`src/analysis`): linear sweep over the decoded stream;
  leaders at branch targets and after terminators; `call` falls through (never
  splits a block). The block walk guarantees forward progress (a leader
  immediately after the start still yields a one-insn block) so it can never
  index before the buffer. Direct-call edges are cross-checked 1227/1227 against
  `objdump -d` on real `notepad.exe` (addresses normalized by the image base).
- **0F-escape alignment**: when the decoder refuses a `0F`-prefixed opcode, the
  streaming disassembler consumes the escape *and* its opcode byte (e.g. `ud2`),
  emitting two `.byte` rows so subsequent bytes stay aligned. Single-instruction
  `decode` still reports `Invalid` for `ud2`, keeping the capstone cross-check's
  refusal contract intact.
- **RE workbench** (`web/`): the wasm playground now renders a hex view, per-section
  entropy bars, and a client-side basic-block CFG alongside the tables, turning the
  demo into a small in-browser reverse-engineering workbench.

## 8. v0.4: DWARF source mapping

- `src/dwarf` decodes `.debug_line` (v4 & v5) into (addr, file, line) rows and
  `.debug_info`/`.debug_abbrev` subprograms into (name, low, high). v5 dir/file
  tables are read by form (string / line_strp / strp / udata / data1 / data16 /
  sec_offset / exprloc / implicit_const), unknown forms skipped by size.
- Raw PE/ELF section bytes are alignment-padded with zeros after the last unit;
  the unit loop stops at `unit_length == 0` and refuses a unit that runs past the
  section, so padding is never misparsed as a unit.
- Verified against the authoritative oracle, not just crafted fixtures: on a real
  gcc `-g` binary (both `-gdwarf-4` and default v5) the line rows equal
  `objdump --dwarf=decodedline` and the subprogram set is {add, main} with sane
  ranges (`test/dwarf_crosscheck.py`). A few of the original hand-crafted v5
  fixtures used non-standard form encodings and were replaced by this real-data
  cross-check.