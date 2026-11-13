# moonbin team board

ARCH / SPEC: frozen contract lives in `INTERFACES.md` (v0.1). This worktree
(`mb-disasm`, branch `feat/disasm`) owns only the `src/disasm` package.

## BUILD

SLICE 1: x86-64 disassembler (common integer + basic SSE subset)
  files:
    - src/disasm/moon.pkg
    - src/disasm/insn.mbt        (Insn, decode/disassemble, hex/reg tables)
    - src/disasm/decode.mbt      (prefixes, REX, ModR/M+SIB, opcode dispatch)
    - src/disasm/decode_test.mbt (28 hand-written unit tests)
    - src/disasm/crosscheck_test.mbt (2 capstone-generated tests; DO NOT EDIT)
    - src/disasm/pkg.generated.mbti  (moon-generated, tracked per repo convention)
    - test/disasm_crosscheck.py  (capstone oracle: emit / verify / notepad / emit-mbt)
  test:    moon test   (and: python -I test/disasm_crosscheck.py verify)
  output:
    RED (before implementation, `moon test`, exit 1):
      Error: [4021] ... crosscheck_test.mbt:30 ... The value identifier disassemble is unbound.
      Error: [4021] ... decode_test.mbt:10 ... The value identifier decode is unbound.
      Failed with ... errors.   (26 errors total)
    GREEN (`moon test`, exit 0):
      Total tests: 36, passed: 36, failed: 0.
      (36 = 28 disasm unit + 2 disasm capstone crosscheck + 6 pre-existing core)
    CAPSTONE (`python -I test/disasm_crosscheck.py verify`, exit 0):
      capstone agreement: 199/199 (100.0%)
      CROSSCHECK PASS
      (199 = 139 fixed-blob insns + 60 notepad.exe .text prefix insns)
    `moon check`: 0 errors (non-test disasm code is warning-free).
  commit:  40b4a81
  notes:
    - Subset only. Unsupported opcodes return Err(Invalid), never guess/panic:
      AVX/VEX/EVEX, x87 FPU, MMX (without 66), 3DNow!, moffs (A0-A3), segment
      mov (8C/8E), far call/jmp (FF /3,/5, 9A, EA), ud2, prefetch, bsf/bsr,
      enter, bound, arpl, etc. Truncated buffer -> Err(Truncated).
    - capstone naming conventions adopted so mnemonic+length agree exactly:
      `movabs` for REX.W B8+rd imm64; `sal` for shift group /6; `lock ` folded
      into the mnemonic when an F0 prefix is present (capstone 5 behavior).
    - op_str is this package's own rendering (lowercase hex immediates,
      "N ptr [base+index*scale+disp]" memory, rip-relative, segment overrides).
      The cross-check compares mnemonic + length ONLY, not op_str text.
    - Cross-check is transitive, both legs green: `moon test` proves the real
      decoder == embedded capstone pairs; `verify` re-derives capstone ==
      embedded pairs. Not a live MoonBit->python pipe (no main package may be
      added outside src/disasm). crosscheck_test.mbt is reproducible via
      `python -I test/disasm_crosscheck.py emit-mbt` (byte-identical on re-run).
    - notepad.exe read read-only from ../moonbin/examples; first 60 .text insns
      (234 bytes, int3 padding + real prologue) all inside the subset.
    - Toolchain facts hit (moon 0.1.20261023): no `?` propagation operator
      (used a sticky-truncation cursor instead); `panic` takes 0 args (used
      `abort` for messages); String[i] returns UInt16; assert_*/inspect need a
      `raise` annotation on enclosing helper fns.
    - Did NOT touch src/core, cmd/main, moon.mod, INTERFACES.md, other packages.
      Commit scoped to src/disasm + test (excluded touched _build artifacts and
      a stray .pyc).