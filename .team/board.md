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

SLICE 2: Mach-O 32/64 both-endian parser (src/macho)
  files:
    - src/macho/moon.pkg
    - src/macho/macho.mbt        (MachO, parse, load-command dispatch, helpers)
    - src/macho/macho_test.mbt   (8 tests: 64-LE + 32-BE golden, 64-BE/32-LE
                                  variants, weak dylib, symbol binding,
                                  LC_UNIXTHREAD arches, malformed, crosscheck dump)
    - src/macho/pkg.generated.mbti  (moon-generated, tracked per repo convention)
    - test/macho_crosscheck.py   (lief oracle: byte-identity gate + header /
                                  segments / sections / symbols / dylibs / entry)
  test:    moon test   (and: python -I test/macho_crosscheck.py)
  output:
    RED (before implementation, `moon test src/macho`, exit 1):
      Error: [4021] ... macho_test.mbt:310:11 ... Value parse not found in package `macho`.
      (repeated for every @macho.parse call; compile failed, no tests ran)
    GREEN (`moon test`, exit 0):
      Total tests: 70, passed: 70, failed: 0.
      (8 macho + 62 pre-existing core/pe/elf/disasm/format)
    `moon test src/macho`: Total tests: 8, passed: 8, failed: 0.
    `moon check --deny-warn`: 0 errors, 0 warnings (exit 0).
    LIEF (`python -I test/macho_crosscheck.py`, exit 0):
      moon test src/macho: Total tests: 8, passed: 8, failed: 0
      PASS: all 77 LIEF cross-checks agree with the MoonBit golden tests
      CROSSCHECK PASS
      (both fixtures byte-identical: MoonBit dump == independent Python regen)
  commit:  1f02569
  notes:
    - Magic read as big-endian u32 maps 0xFEEDFACE/0xFEEDFACF/0xCEFAEDFE/0xCFFAEDFE
      to (class, endian); anything else -> BadMagic. All four 32/64 x LE/BE combos
      unit-tested.
    - Load commands: LC_SEGMENT/LC_SEGMENT_64 (segments+sections), LC_SYMTAB
      (nlist+strtab), LC_LOAD_DYLIB/LC_LOAD_WEAK_DYLIB (imports), LC_MAIN and
      LC_UNIXTHREAD (entry). Unknown commands skipped by cmdsize. Segment field
      widths follow the command id, not the file class.
    - entry: LC_MAIN file offset resolved to a VA through the covering segment
      (matches lief.entrypoint); LC_UNIXTHREAD reads the arch PC (x86 flavor 1/7,
      x86-64 flavor 4, ARM flavor 1, ARM64 flavor 6, PPC flavor 1, PPC64 flavor 5).
      LC_MAIN wins if both present; 0 if neither. Unknown flavor/cputype -> Invalid.
    - Symbol kind from n_type (undefined/absolute/section/prebound/indirect/debug);
      bind local/private/weak/global from N_EXT/N_PEXT/n_desc weak bits. nlist has
      no size field -> Symbol.size = 0. shndx = n_sect (1-based) or -1 when 0.
      Defined non-stab symbols -> exports (ordinal 0, rva = n_value).
    - Bounds-checked: header/sizeofcmds/ncmds, per-command cmdsize, segment/section
      file ranges (S_ZEROFILL / S_THREAD_LOCAL_ZEROFILL exempt), symtab/strtab
      ranges, string offsets + termination, dylib name offset, thread-state length.
      Refuses Truncated/BadMagic/Invalid; never panics or guesses.
    - LIEF 0.16.4 caveat: for big-endian LC_UNIXTHREAD its convenience
      entrypoint/pc reads the PPC state as little-endian (wrong: 0x98111000 vs the
      correct srr0 0x1198). The cross-check instead reads srr0 from lief's raw
      thread_command.state (big-endian) == the parser's behavior; header/sections/
      symbols/dylibs compared directly. Single-segment fixtures make lief log benign
      "not in __LINKEDIT" warnings (suppressed); parsing unaffected.
    - Cross-check is transitive on identical bytes: golden tests assert values on
      bytes B; the dump emits B; Python regenerates B and asserts byte-identity;
      lief parses B and reports the same values. Not a live MoonBit->python pipe
      (no main package added outside src/macho).
    - Did NOT touch core/pe/elf/disasm/format/cmd/moon.mod/INTERFACES.md. Commit
      scoped to src/macho + test/macho_crosscheck.py (_build is gitignored).