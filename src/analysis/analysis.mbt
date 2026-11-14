/// A basic block over the decoded instruction stream: the half-open address
/// range `[start, end)` plus its control-flow successors.
///
/// `succs` holds absolute addresses, not block indices. A successor may point
/// outside the swept buffer (e.g. a jump into another section) or, for a jcc
/// that ends the buffer, one past the last byte.
pub(all) struct Block {
  start : Int64
  /// Exclusive end address.
  end : Int64
  succs : Array[Int64]
} derive(Debug)

/// One hex digit value, or None for a non-hex character.
fn hex_digit(c : Int) -> Int? {
  if c >= 48 && c <= 57 {
    Some(c - 48)
  } else if c >= 97 && c <= 102 {
    Some(c - 87)
  } else if c >= 65 && c <= 70 {
    Some(c - 55)
  } else {
    None
  }
}

/// Parse an absolute address rendered as `0x` + lowercase/uppercase hex
/// (the disasm package's branch-target format). Returns None for anything
/// else: register operands, memory operands, empty strings, >16 digits.
fn parse_hex_addr(s : String) -> Int64? {
  let n = s.length()
  if n < 3 || n > 18 {
    return None
  }
  if s[0].to_int() != 48 || s[1].to_int() != 120 {
    return None
  }
  let mut v : Int64 = 0L
  for i = 2; i < n; i = i + 1 {
    match hex_digit(s[i].to_int()) {
      Some(d) => v = v * 16L + d.to_int64()
      None => return None
    }
  }
  Some(v)
}

/// The decoder folds a F0 prefix into the mnemonic ("lock call"); classify
/// both forms. `lock` on control flow is architecturally invalid but the
/// decoder reports it faithfully, so the analysis stays consistent with it.
fn is_call(mn : String) -> Bool {
  mn == "call" || mn == "lock call"
}

fn is_jmp(mn : String) -> Bool {
  mn == "jmp" || mn == "lock jmp"
}

fn is_ret(mn : String) -> Bool {
  mn == "ret" || mn == "lock ret"
}

/// Conditional branch: every decoder jcc mnemonic is "j" + condition code
/// and none equals "jmp".
fn is_jcc(mn : String) -> Bool {
  mn.length() >= 2 && mn[0].to_int() == 106 && mn != "jmp"
}

fn is_terminator(mn : String) -> Bool {
  is_jmp(mn) || is_jcc(mn) || is_ret(mn)
}

/// Index of the instruction at address `t` in the address-sorted `insns`,
/// or -1 when `t` is not an instruction boundary inside the buffer.
fn insn_index_at(insns : Array[@disasm.Insn], t : Int64) -> Int {
  let mut lo = 0
  let mut hi = insns.length() - 1
  while lo <= hi {
    let mid = (lo + hi) / 2
    let a = insns[mid].addr
    if a == t {
      return mid
    } else if a < t {
      lo = mid + 1
    } else {
      hi = mid - 1
    }
  }
  -1
}

/// Basic-block control-flow graph via linear sweep.
///
/// Decodes the whole buffer with `@disasm.disassemble` (unknown opcodes
/// become `.byte` rows that fall through; a truncated tail is dropped).
/// Leaders are: the first instruction, every instruction right after a
/// terminator (jmp/jcc/ret), and every jmp/jcc target that lands on an
/// instruction boundary inside the buffer. A target landing mid-instruction
/// does not force a split (that would overlap blocks); the edge is still
/// recorded in `succs`.
///
/// Successors: jcc -> [target, fallthrough], direct jmp -> [target],
/// indirect jmp -> [] (target unknown), ret -> []. A block that ends without
/// a terminator falls through to the next block, or has no successor at the
/// buffer end. `call` never ends or splits a block: it falls through, and
/// call targets do not create leaders. Blocks are sorted by start and
/// non-overlapping.
pub fn cfg(code : Bytes, base : Int64) -> Array[Block] {
  let insns = @disasm.disassemble(code, base, code.length())
  let n = insns.length()
  let out : Array[Block] = []
  if n == 0 {
    return out
  }
  // Mark leaders by instruction index (addresses are strictly increasing).
  let leader : Array[Bool] = Array::make(n, false)
  leader[0] = true
  for i = 0; i < n; i = i + 1 {
    let ins = insns[i]
    if is_terminator(ins.mnemonic) {
      if i + 1 < n {
        leader[i + 1] = true
      }
    }
    if is_jmp(ins.mnemonic) || is_jcc(ins.mnemonic) {
      match parse_hex_addr(ins.op_str) {
        Some(t) => {
          let j = insn_index_at(insns, t)
          if j >= 0 {
            leader[j] = true
          }
        }
        None => ()
      }
    }
  }
  // Walk leaders, extending each block to its terminator or the next leader.
  let mut i = 0
  while i < n {
    let start = insns[i].addr
    let mut j = i
    let mut term = false
    while j < n {
      if is_terminator(insns[j].mnemonic) {
        j = j + 1
        term = true
        break
      }
      if j + 1 < n && leader[j + 1] {
        break
      }
      j = j + 1
    }
    // A leader immediately after the block start still yields a one-insn
    // block; guarantee forward progress so we never read insns[-1].
    if j == i {
      j = i + 1
    }
    let last = insns[j - 1]
    let end = last.addr + last.len.to_int64()
    let succs : Array[Int64] = []
    if term {
      let mn = last.mnemonic
      if is_jcc(mn) {
        match parse_hex_addr(last.op_str) {
          Some(t) => {
            succs.push(t)
            succs.push(end)
          }
          None => succs.push(end)
        }
      } else if is_jmp(mn) {
        match parse_hex_addr(last.op_str) {
          Some(t) => succs.push(t)
          None => ()
        }
      }
      // ret: no successors
    } else if j < n {
      succs.push(insns[j].addr)
    }
    out.push({ start, end, succs })
    i = j
  }
  out
}

/// Direct call edges `(caller_insn_addr, callee_target)` in sweep order.
///
/// Only `call rel32` (E8) instructions produce edges: their operand is an
/// absolute address in the disasm's op_str. Indirect calls (`call rax`,
/// `call qword ptr [...]`) have no static target and are skipped, as are
/// `.byte` rows. Duplicates are kept: one edge per call instruction.
pub fn callgraph(code : Bytes, base : Int64) -> Array[(Int64, Int64)] {
  let insns = @disasm.disassemble(code, base, code.length())
  let out : Array[(Int64, Int64)] = []
  for i = 0; i < insns.length(); i = i + 1 {
    let ins = insns[i]
    if is_call(ins.mnemonic) {
      match parse_hex_addr(ins.op_str) {
        Some(t) => out.push((ins.addr, t))
        None => ()
      }
    }
  }
  out
}