// Hand-crafted x86-64 blobs pinning the frozen analysis contract:
//   Block { start, end (exclusive), succs }
//   cfg: linear sweep, split at jmp/jcc targets and after jmp/jcc/ret;
//        jcc -> [target, fallthrough], jmp -> [target], ret -> [],
//        call falls through (never ends or splits a block),
//        .byte rows fall through; blocks sorted, non-overlapping.
//   callgraph: (caller_insn_addr, callee_target) for direct calls only.

fn xb(vals : Array[Int]) -> Bytes {
  Bytes::makei(vals.length(), fn(i) { vals[i].to_byte() })
}

fn assert_blocks(
  got : Array[Block],
  expected : Array[(Int64, Int64, Array[Int64])]
) -> Unit raise {
  assert_eq(got.length(), expected.length())
  for i = 0; i < expected.length(); i = i + 1 {
    let (s, e, succs) = expected[i]
    assert_eq(got[i].start, s)
    assert_eq(got[i].end, e)
    assert_eq(got[i].succs.length(), succs.length())
    for j = 0; j < succs.length(); j = j + 1 {
      assert_eq(got[i].succs[j], succs[j])
    }
  }
}

fn assert_edges(got : Array[(Int64, Int64)], expected : Array[(Int64, Int64)]) -> Unit raise {
  assert_eq(got.length(), expected.length())
  for i = 0; i < expected.length(); i = i + 1 {
    assert_eq(got[i].0, expected[i].0)
    assert_eq(got[i].1, expected[i].1)
  }
}

test "cfg: empty code yields no blocks, no edges" {
  let empty = xb([])
  assert_blocks(cfg(empty, 0x1000L), [])
  assert_edges(callgraph(empty, 0x1000L), [])
}

test "cfg: straight-line code ending in ret is one block" {
  // 0x1000: mov rbp, rsp / sub rsp, 0x20 / ret
  let code = xb([0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xC3])
  assert_blocks(cfg(code, 0x1000L), [(0x1000L, 0x1008L, [])])
  assert_edges(callgraph(code, 0x1000L), [])
}

test "cfg: jcc splits at target and fallthrough, two succs" {
  // 0x1000: xor rax, rax      (3)
  // 0x1003: je 0x1009         (2)
  // 0x1005: inc rax           (3)
  // 0x1008: ret               (1)
  // 0x1009: dec rax           (3)
  // 0x100c: ret               (1)
  let code = xb([
    0x48, 0x31, 0xC0, 0x74, 0x04, 0x48, 0xFF, 0xC0, 0xC3, 0x48, 0xFF, 0xC8,
    0xC3,
  ])
  assert_blocks(cfg(code, 0x1000L), [
    (0x1000L, 0x1005L, [0x1009L, 0x1005L]),
    (0x1005L, 0x1009L, []),
    (0x1009L, 0x100DL, []),
  ])
}

test "cfg: call falls through and never splits a block" {
  // 0x1000: call 0x100a       (5)
  // 0x1005: inc rax           (3)
  // 0x1008: ret               (1)
  // 0x1009: int3              (1)
  // 0x100a: xor rax, rax      (3)
  // 0x100d: ret               (1)
  let code = xb([
    0xE8, 0x05, 0x00, 0x00, 0x00, 0x48, 0xFF, 0xC0, 0xC3, 0xCC, 0x48, 0x31,
    0xC0, 0xC3,
  ])
  assert_blocks(cfg(code, 0x1000L), [
    (0x1000L, 0x1009L, []),
    (0x1009L, 0x100EL, []),
  ])
  assert_edges(callgraph(code, 0x1000L), [(0x1000L, 0x100AL)])
}

test "cfg: jmp rel32 forward and rel8 backward loop" {
  // 0x1000: jmp 0x100a        (5)
  // 0x1005: inc rax           (3)
  // 0x1008: jmp 0x1000        (2)
  // 0x100a: ret               (1)
  let code = xb([
    0xE9, 0x05, 0x00, 0x00, 0x00, 0x48, 0xFF, 0xC0, 0xEB, 0xF6, 0xC3,
  ])
  assert_blocks(cfg(code, 0x1000L), [
    (0x1000L, 0x1005L, [0x100AL]),
    (0x1005L, 0x100AL, [0x1000L]),
    (0x100AL, 0x100BL, []),
  ])
  assert_edges(callgraph(code, 0x1000L), [])
}

test "cfg: near jcc, ret imm, fallthrough edge into next block" {
  // 0x1000: jne 0x100c        (6)
  // 0x1006: ret 8             (3)
  // 0x1009: inc rax           (3)
  // 0x100c: ret               (1)
  let code = xb([
    0x0F, 0x85, 0x06, 0x00, 0x00, 0x00, 0xC2, 0x08, 0x00, 0x48, 0xFF, 0xC0,
    0xC3,
  ])
  assert_blocks(cfg(code, 0x1000L), [
    (0x1000L, 0x1006L, [0x100CL, 0x1006L]),
    (0x1006L, 0x1009L, []),
    (0x1009L, 0x100CL, [0x100CL]),
    (0x100CL, 0x100DL, []),
  ])
}

test "cfg: indirect call and jmp; callgraph keeps direct calls only" {
  // 0x1000: call rax          (2)
  // 0x1002: jmp rax           (2)  -> terminator, target unknown
  // 0x1004: ret               (1)
  let code = xb([0xFF, 0xD0, 0xFF, 0xE0, 0xC3])
  assert_blocks(cfg(code, 0x1000L), [
    (0x1000L, 0x1004L, []),
    (0x1004L, 0x1005L, []),
  ])
  assert_edges(callgraph(code, 0x1000L), [])
}

test "cfg: .byte rows fall through without splitting" {
  // 0x1000: ud2 (0f 0b) -> two .byte rows (outside decoder subset)
  // 0x1002: inc rax           (3)
  // 0x1005: ret               (1)
  let code = xb([0x0F, 0x0B, 0x48, 0xFF, 0xC0, 0xC3])
  assert_blocks(cfg(code, 0x1000L), [(0x1000L, 0x1006L, [])])
  assert_edges(callgraph(code, 0x1000L), [])
}

test "cfg: truncated tail bytes are dropped, not guessed" {
  // 0x1000: inc rax           (3)
  // 0x1003: e8 00 00 -> truncated call, sweep stops here
  let code = xb([0x48, 0xFF, 0xC0, 0xE8, 0x00, 0x00])
  assert_blocks(cfg(code, 0x1000L), [(0x1000L, 0x1003L, [])])
  assert_edges(callgraph(code, 0x1000L), [])
}

test "callgraph: repeated direct calls keep sweep order and duplicates" {
  // 0x1000: call 0x1010       (5)
  // 0x1005: call 0x1010       (5)
  // 0x100a: call 0x1010       (5)
  // 0x100f: ret               (1)
  // 0x1010: ret               (1)
  let code = xb([
    0xE8, 0x0B, 0x00, 0x00, 0x00, 0xE8, 0x06, 0x00, 0x00, 0x00, 0xE8, 0x01,
    0x00, 0x00, 0x00, 0xC3, 0xC3,
  ])
  assert_edges(callgraph(code, 0x1000L), [
    (0x1000L, 0x1010L),
    (0x1005L, 0x1010L),
    (0x100AL, 0x1010L),
  ])
  assert_blocks(cfg(code, 0x1000L), [
    (0x1000L, 0x1010L, []),
    (0x1010L, 0x1011L, []),
  ])
}

test "cfg: nonzero base address is honored everywhere" {
  let base = 0x140001000L
  // base+0: call base+10      (5)
  // base+5: ret               (1)
  // base+6: xor rax, rax      (3)
  // base+9: ret               (1)
  let code = xb([
    0xE8, 0x05, 0x00, 0x00, 0x00, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
  ])
  assert_blocks(cfg(code, base), [
    (base, base + 6L, []),
    (base + 6L, base + 10L, []),
  ])
  assert_edges(callgraph(code, base), [(base, base + 10L)])
}

test "cfg: jcc as last instruction still has two succs" {
  // 0x1000: je 0x1000 (self)  (2); fallthrough points past the buffer
  let code = xb([0x74, 0xFE])
  assert_blocks(cfg(code, 0x1000L), [(0x1000L, 0x1002L, [0x1000L, 0x1002L])])
}

test "cfg: mixed blob stays sorted and non-overlapping; mid-insn target kept as edge" {
  // 0x1000: xor rax, rax      (3)
  // 0x1003: je 0x1007         (2)
  // 0x1005: jmp 0x100a        (2)  -> 0x100a lands mid-call: no split there
  // 0x1007: ret               (1)
  // 0x1008: call 0x100f       (5)
  // 0x100d: ret               (1)
  // 0x100e: nop               (1)
  // 0x100f: ret               (1)
  let code = xb([
    0x48, 0x31, 0xC0, 0x74, 0x02, 0xEB, 0x03, 0xC3, 0xE8, 0x02, 0x00, 0x00,
    0x00, 0xC3, 0x90, 0xC3,
  ])
  let blocks = cfg(code, 0x1000L)
  assert_blocks(blocks, [
    (0x1000L, 0x1005L, [0x1007L, 0x1005L]),
    (0x1005L, 0x1007L, [0x100AL]),
    (0x1007L, 0x1008L, []),
    (0x1008L, 0x100EL, []),
    (0x100EL, 0x1010L, []),
  ])
  // generic invariants: sorted, non-overlapping, inside the buffer
  assert_true(blocks.length() > 0)
  assert_eq(blocks[0].start, 0x1000L)
  for i = 0; i < blocks.length(); i = i + 1 {
    assert_true(blocks[i].start < blocks[i].end)
    assert_true(blocks[i].end <= 0x1010L)
    if i > 0 {
      assert_true(blocks[i - 1].end <= blocks[i].start)
    }
  }
  assert_edges(callgraph(code, 0x1000L), [(0x1008L, 0x100FL)])
}
