/// Per-instruction decoder state: prefixes + cursor.
///
/// Reads go through the wrapper methods below, which return a plain value and
/// set `trunc` on end-of-buffer. `decode_inner` turns any `trunc` into a
/// `Truncated` refusal, so a short buffer never yields a fabricated insn.
priv struct Dec {
  r : @core.Reader
  addr : Int64
  /// Cursor position at instruction start; the reader may be shared across a
  /// whole disassembly, so relative targets must subtract this.
  start : Int
  mut rex : Int
  mut has_rex : Bool
  mut opsize : Int
  mut addrsize : Int
  mut seg : String
  mut lock : Bool
  mut rep : Int
  mut has66 : Bool
  mut trunc : Bool
}

/// A decoded ModR/M (+SIB) operand.
priv struct RM {
  /// reg field with REX.R applied (register operand of normal opcodes).
  reg : Int
  /// raw 3-bit reg field (group /opcode selection; REX.R does not apply).
  raw_reg : Int
  /// rendered operand text ("rax" or "qword ptr [rbp-0x8]").
  text : String
  is_mem : Bool
}

fn Dec::u8(self : Dec) -> Int {
  match self.r.u8() {
    Some(v) => v
    None => {
      self.trunc = true
      0
    }
  }
}

fn Dec::i8(self : Dec) -> Int {
  match self.r.i8() {
    Some(v) => v
    None => {
      self.trunc = true
      0
    }
  }
}

fn Dec::u16(self : Dec) -> Int64 {
  match self.r.u16(le) {
    Some(v) => v
    None => {
      self.trunc = true
      0L
    }
  }
}

fn Dec::u32(self : Dec) -> Int64 {
  match self.r.u32(le) {
    Some(v) => v
    None => {
      self.trunc = true
      0L
    }
  }
}

fn Dec::u64(self : Dec) -> Int64 {
  match self.r.u64(le) {
    Some(v) => v
    None => {
      self.trunc = true
      0L
    }
  }
}

fn Dec::peek1(self : Dec) -> Int {
  match self.r.peek(1) {
    Some(b) => b[0].to_int()
    None => {
      self.trunc = true
      0
    }
  }
}

fn Dec::rex_w(self : Dec) -> Bool {
  (self.rex & 8) != 0
}

fn Dec::rex_r(self : Dec) -> Int {
  (self.rex & 4) >> 2
}

fn Dec::rex_x(self : Dec) -> Int {
  (self.rex & 2) >> 1
}

fn Dec::rex_b(self : Dec) -> Int {
  self.rex & 1
}

/// Default operand size of push/pop/call/jmp in long mode.
fn Dec::push_size(self : Dec) -> Int {
  if self.has66 && self.rex_w() == false {
    16
  } else {
    64
  }
}

/// Consume legacy prefixes, then at most one REX. Sets opsize/addrsize.
fn Dec::prefixes(self : Dec) -> Unit {
  while true {
    let b = self.peek1()
    if self.trunc {
      break
    }
    if b == 0x66 {
      self.has66 = true
    } else if b == 0x67 {
      self.addrsize = 32
    } else if b == 0xF0 {
      self.lock = true
    } else if b == 0xF2 || b == 0xF3 {
      self.rep = b
    } else if b == 0x2E {
      self.seg = "cs:"
    } else if b == 0x36 {
      self.seg = "ss:"
    } else if b == 0x3E {
      self.seg = "ds:"
    } else if b == 0x26 {
      self.seg = "es:"
    } else if b == 0x64 {
      self.seg = "fs:"
    } else if b == 0x65 {
      self.seg = "gs:"
    } else {
      break
    }
    let _ = self.r.skip(1)
  }
  if self.trunc {
    return
  }
  let b = self.peek1()
  if self.trunc == false && b >= 0x40 && b <= 0x4F {
    self.rex = b
    self.has_rex = true
    let _ = self.r.skip(1)
  }
  self.opsize = if self.rex_w() {
    64
  } else if self.has66 {
    16
  } else {
    32
  }
}

/// Read ModR/M (+SIB, displacement) and render the r/m operand.
///
/// `reg_size` names the register for mod=11 (128 = xmm); `ptr_size` is the
/// memory operand width in bytes (0 suppresses the "N ptr" text, for lea).
fn Dec::read_rm(self : Dec, reg_size : Int, ptr_size : Int) -> RM {
  let m = self.u8()
  let mod = (m >> 6) & 3
  let raw_reg = (m >> 3) & 7
  let reg = raw_reg | (self.rex_r() << 3)
  let rm = m & 7
  if mod == 3 {
    let idx = rm | (self.rex_b() << 3)
    return {
      reg,
      raw_reg,
      text: gpr_name(reg_size, idx, self.has_rex),
      is_mem: false,
    }
  }
  let a64 = self.addrsize == 64
  let bsize = if a64 {
    64
  } else {
    32
  }
  let parts : Array[String] = []
  let mut disp : Int64 = 0L
  let mut have_disp = false
  if rm == 4 {
    let sib = self.u8()
    let scale = 1 << ((sib >> 6) & 3)
    let index = ((sib >> 3) & 7) | (self.rex_x() << 3)
    let base = (sib & 7) | (self.rex_b() << 3)
    if mod == 0 && (sib & 7) == 5 {
      disp = self.u32()
      have_disp = true
    } else {
      parts.push(gpr_name(bsize, base, self.has_rex))
    }
    if index != 4 {
      let it = gpr_name(bsize, index, self.has_rex)
      parts.push(if scale == 1 {
        it
      } else {
        it + "*" + scale.to_string()
      })
    }
  } else if mod == 0 && rm == 5 {
    disp = self.u32()
    have_disp = true
    if a64 {
      parts.push("rip")
    }
  } else {
    let base = rm | (self.rex_b() << 3)
    parts.push(gpr_name(bsize, base, self.has_rex))
  }
  if mod == 1 {
    disp = self.i8().to_int64()
    have_disp = true
  } else if mod == 2 {
    disp = self.u32()
    have_disp = true
  }
  let mut inner = ""
  for p in parts {
    inner = inner + (if inner == "" {
      ""
    } else {
      "+"
    }) + p
  }
  if have_disp && disp != 0L {
    if disp < 0L {
      inner = inner + "-" + hex_u64(-disp)
    } else {
      inner = inner + "+" + hex_u64(disp)
    }
  } else if inner == "" {
    inner = hex_u64(disp)
  }
  {
    reg,
    raw_reg,
    text: ptr_text(ptr_size) + self.seg + "[" + inner + "]",
    is_mem: true,
  }
}

/// Immediate at the current operand size (imm16, or imm32 sign-extended).
fn Dec::read_imm(self : Dec, size : Int) -> Int64 {
  if size == 16 {
    self.u16()
  } else {
    sext32(self.u32())
  }
}

/// Branch target text: absolute address = addr + encoded length + rel.
fn Dec::target(self : Dec, rel : Int64) -> String {
  hex_u64(self.addr + (self.r.position() - self.start).to_int64() + rel)
}

fn decode_inner(
  r : @core.Reader,
  addr : Int64
) -> Result[(String, String), @core.ParseError] {
  let d : Dec = {
    r,
    addr,
    start: r.position(),
    rex: 0,
    has_rex: false,
    opsize: 32,
    addrsize: 64,
    seg: "",
    lock: false,
    rep: 0,
    has66: false,
    trunc: false,
  }
  d.prefixes()
  let res = d.insn()
  if d.trunc {
    return Err(@core.ParseError::Truncated("x86 instruction"))
  }
  match res {
    Ok((mn, ops)) => if d.lock {
      Ok(("lock " + mn, ops))
    } else {
      Ok((mn, ops))
    }
    Err(e) => Err(e)
  }
}

/// One-byte opcode dispatch (0x0F escapes to `two_byte`).
fn Dec::insn(self : Dec) -> Result[(String, String), @core.ParseError] {
  let op = self.u8()
  if op == 0x0F {
    return self.two_byte()
  }
  // Arithmetic block: 00-05 / 08-0D / ... / 38-3D.
  if op < 0x3E && (op & 7) < 6 {
    let name = arith_names[op >> 3]
    let form = op & 7
    if form == 0 || form == 1 {
      let sz = if form == 0 {
        8
      } else {
        self.opsize
      }
      let rm = self.read_rm(sz, sz / 8)
      return Ok((name, rm.text + ", " + gpr_name(sz, rm.reg, self.has_rex)))
    }
    if form == 2 || form == 3 {
      let sz = if form == 2 {
        8
      } else {
        self.opsize
      }
      let rm = self.read_rm(sz, sz / 8)
      return Ok((name, gpr_name(sz, rm.reg, self.has_rex) + ", " + rm.text))
    }
    if form == 4 {
      let imm = self.u8()
      return Ok((name, "al, " + hex_u64(imm.to_int64())))
    }
    let imm = self.read_imm(self.opsize)
    return Ok((
      name,
      gpr_name(self.opsize, 0, self.has_rex) + ", " + hex_u64(imm),
    ))
  }
  if op >= 0x50 && op <= 0x57 {
    let sz = self.push_size()
    let reg = (op - 0x50) | (self.rex_b() << 3)
    return Ok(("push", gpr_name(sz, reg, self.has_rex)))
  }
  if op >= 0x58 && op <= 0x5F {
    let sz = self.push_size()
    let reg = (op - 0x58) | (self.rex_b() << 3)
    return Ok(("pop", gpr_name(sz, reg, self.has_rex)))
  }
  if op == 0x63 {
    let dsz = if self.rex_w() {
      64
    } else {
      32
    }
    let ssz = if self.rex_w() {
      32
    } else {
      16
    }
    let rm = self.read_rm(ssz, ssz / 8)
    return Ok((
      "movsxd",
      gpr_name(dsz, rm.reg, self.has_rex) + ", " + rm.text,
    ))
  }
  if op == 0x68 {
    return Ok(("push", hex_u64(sext32(self.u32()))))
  }
  if op == 0x6A {
    return Ok(("push", hex_u64(sext8(self.u8()))))
  }
  if op == 0x69 || op == 0x6B {
    let rm = self.read_rm(self.opsize, self.opsize / 8)
    let imm = if op == 0x69 {
      self.read_imm(self.opsize)
    } else {
      sext8(self.u8())
    }
    return Ok((
      "imul",
      gpr_name(self.opsize, rm.reg, self.has_rex) +
      ", " +
      rm.text +
      ", " +
      hex_u64(imm),
    ))
  }
  if op >= 0x70 && op <= 0x7F {
    let rel = self.i8().to_int64()
    return Ok(("j" + cc_names[op - 0x70], self.target(rel)))
  }
  if op == 0x80 || op == 0x81 || op == 0x83 {
    let sz = if op == 0x80 {
      8
    } else {
      self.opsize
    }
    let rm = self.read_rm(sz, sz / 8)
    let imm = if op == 0x81 {
      self.read_imm(sz)
    } else if op == 0x83 {
      sext8(self.u8())
    } else {
      self.u8().to_int64()
    }
    return Ok((arith_names[rm.raw_reg], rm.text + ", " + hex_u64(imm)))
  }
  if op == 0x84 || op == 0x85 || op == 0x86 || op == 0x87 {
    let sz = if (op & 1) == 0 {
      8
    } else {
      self.opsize
    }
    let rm = self.read_rm(sz, sz / 8)
    let name = if op < 0x86 {
      "test"
    } else {
      "xchg"
    }
    return Ok((name, rm.text + ", " + gpr_name(sz, rm.reg, self.has_rex)))
  }
  if op >= 0x88 && op <= 0x8B {
    let sz = if (op & 1) == 0 {
      8
    } else {
      self.opsize
    }
    let rm = self.read_rm(sz, sz / 8)
    if op < 0x8A {
      return Ok(("mov", rm.text + ", " + gpr_name(sz, rm.reg, self.has_rex)))
    }
    return Ok(("mov", gpr_name(sz, rm.reg, self.has_rex) + ", " + rm.text))
  }
  if op == 0x8D {
    let rm = self.read_rm(self.opsize, 0)
    if rm.is_mem == false {
      return Err(invalid("lea with register operand"))
    }
    return Ok((
      "lea",
      gpr_name(self.opsize, rm.reg, self.has_rex) + ", " + rm.text,
    ))
  }
  if op == 0x8F {
    let sz = self.push_size()
    let rm = self.read_rm(sz, sz / 8)
    if rm.raw_reg != 0 {
      return Err(invalid("8F /reg != 0"))
    }
    return Ok(("pop", rm.text))
  }
  if op >= 0x90 && op <= 0x97 {
    if op == 0x90 && self.rex_b() == 0 {
      return Ok(("nop", ""))
    }
    let reg = (op - 0x90) | (self.rex_b() << 3)
    return Ok((
      "xchg",
      gpr_name(self.opsize, 0, self.has_rex) +
      ", " +
      gpr_name(self.opsize, reg, self.has_rex),
    ))
  }
  if op == 0x98 || op == 0x99 {
    let name = match self.opsize {
      16 => if op == 0x98 {
        "cbw"
      } else {
        "cwd"
      }
      64 => if op == 0x98 {
        "cdqe"
      } else {
        "cqo"
      }
      _ => if op == 0x98 {
        "cwde"
      } else {
        "cdq"
      }
    }
    return Ok((name, ""))
  }
  if op == 0x9C || op == 0x9D {
    let base = if op == 0x9C {
      "pushf"
    } else {
      "popf"
    }
    let name = if self.has66 && self.rex_w() == false {
      base
    } else {
      base + "q"
    }
    return Ok((name, ""))
  }
  if op == 0xA8 {
    return Ok(("test", "al, " + hex_u64(self.u8().to_int64())))
  }
  if op == 0xA9 {
    let imm = self.read_imm(self.opsize)
    return Ok((
      "test",
      gpr_name(self.opsize, 0, self.has_rex) + ", " + hex_u64(imm),
    ))
  }
  if op >= 0xB0 && op <= 0xB7 {
    let reg = (op - 0xB0) | (self.rex_b() << 3)
    let imm = self.u8()
    return Ok((
      "mov",
      gpr_name(8, reg, self.has_rex) + ", " + hex_u64(imm.to_int64()),
    ))
  }
  if op >= 0xB8 && op <= 0xBF {
    let reg = (op - 0xB8) | (self.rex_b() << 3)
    if self.rex_w() {
      let imm = self.u64()
      return Ok((
        "movabs",
        gpr_name(64, reg, self.has_rex) + ", " + hex_u64(imm),
      ))
    }
    let imm = self.read_imm(self.opsize)
    return Ok((
      "mov",
      gpr_name(self.opsize, reg, self.has_rex) + ", " + hex_u64(imm),
    ))
  }
  if op == 0xC0 || op == 0xC1 || op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3 {
    let sz = if (op & 1) == 0 {
      8
    } else {
      self.opsize
    }
    let rm = self.read_rm(sz, sz / 8)
    let count = if op < 0xC2 {
      hex_u64(self.u8().to_int64())
    } else if op < 0xD2 {
      "1"
    } else {
      "cl"
    }
    return Ok((shift_names[rm.raw_reg], rm.text + ", " + count))
  }
  if op == 0xC2 {
    return Ok(("ret", hex_u64(self.u16())))
  }
  if op == 0xC3 {
    return Ok(("ret", ""))
  }
  if op == 0xC6 || op == 0xC7 {
    let sz = if op == 0xC6 {
      8
    } else {
      self.opsize
    }
    let rm = self.read_rm(sz, sz / 8)
    if rm.raw_reg != 0 {
      return Err(invalid("C6/C7 /reg != 0"))
    }
    let imm = if op == 0xC6 {
      self.u8().to_int64()
    } else {
      self.read_imm(sz)
    }
    return Ok(("mov", rm.text + ", " + hex_u64(imm)))
  }
  if op == 0xC9 {
    return Ok(("leave", ""))
  }
  if op == 0xCC {
    return Ok(("int3", ""))
  }
  if op == 0xCD {
    return Ok(("int", hex_u64(self.u8().to_int64())))
  }
  if op == 0xE8 || op == 0xE9 {
    let rel = sext32(self.u32())
    let name = if op == 0xE8 {
      "call"
    } else {
      "jmp"
    }
    return Ok((name, self.target(rel)))
  }
  if op == 0xEB {
    let rel = self.i8().to_int64()
    return Ok(("jmp", self.target(rel)))
  }
  if op == 0xF4 || op == 0xF5 || (op >= 0xF8 && op <= 0xFD) {
    let name = match op {
      0xF4 => "hlt"
      0xF5 => "cmc"
      0xF8 => "clc"
      0xF9 => "stc"
      0xFA => "cli"
      0xFB => "sti"
      0xFC => "cld"
      _ => "std"
    }
    return Ok((name, ""))
  }
  if op == 0xF6 || op == 0xF7 {
    let sz = if op == 0xF6 {
      8
    } else {
      self.opsize
    }
    let rm = self.read_rm(sz, sz / 8)
    if rm.raw_reg == 0 || rm.raw_reg == 1 {
      let imm = if op == 0xF6 {
        self.u8().to_int64()
      } else {
        self.read_imm(sz)
      }
      return Ok(("test", rm.text + ", " + hex_u64(imm)))
    }
    let name = match rm.raw_reg {
      2 => "not"
      3 => "neg"
      4 => "mul"
      5 => "imul"
      6 => "div"
      _ => "idiv"
    }
    return Ok((name, rm.text))
  }
  if op == 0xFE {
    let rm = self.read_rm(8, 1)
    if rm.raw_reg > 1 {
      return Err(invalid("FE /reg > 1"))
    }
    let name = if rm.raw_reg == 0 {
      "inc"
    } else {
      "dec"
    }
    return Ok((name, rm.text))
  }
  if op == 0xFF {
    let raw = (self.peek1() >> 3) & 7
    if raw == 0 || raw == 1 {
      let rm = self.read_rm(self.opsize, self.opsize / 8)
      let name = if raw == 0 {
        "inc"
      } else {
        "dec"
      }
      return Ok((name, rm.text))
    }
    if raw == 2 || raw == 4 || raw == 6 {
      let sz = self.push_size()
      let rm = self.read_rm(sz, sz / 8)
      let name = if raw == 2 {
        "call"
      } else if raw == 4 {
        "jmp"
      } else {
        "push"
      }
      return Ok((name, rm.text))
    }
    return Err(invalid("FF /3 or /5 (far call/jmp)"))
  }
  Err(invalid("unsupported one-byte opcode"))
}

/// Two-byte (0F) opcode dispatch: jcc/setcc/cmovcc, movzx/movsx, SSE, groups.
fn Dec::two_byte(self : Dec) -> Result[(String, String), @core.ParseError] {
  let op = self.u8()
  if op == 0x05 || op == 0x07 {
    return Ok((if op == 0x05 {
      "syscall"
    } else {
      "sysret"
    }, ""))
  }
  if op == 0x10 || op == 0x11 || op == 0x28 || op == 0x29 {
    let mut name = ""
    let mut ptr = 16
    if op < 0x12 {
      if self.rep == 0xF3 {
        name = "movss"
        ptr = 4
      } else if self.rep == 0xF2 {
        name = "movsd"
        ptr = 8
      } else if self.has66 {
        name = "movupd"
      } else {
        name = "movups"
      }
    } else if self.has66 {
      name = "movapd"
    } else {
      name = "movaps"
    }
    let rm = self.read_rm(128, ptr)
    let xmm = gpr_name(128, rm.reg, self.has_rex)
    if op == 0x10 || op == 0x28 {
      return Ok((name, xmm + ", " + rm.text))
    }
    return Ok((name, rm.text + ", " + xmm))
  }
  if op == 0x1E {
    if self.rep == 0xF3 {
      let m = self.u8()
      if m == 0xFA {
        return Ok(("endbr64", ""))
      }
    }
    return Err(invalid("0F 1E (not endbr64)"))
  }
  if op == 0x1F {
    let rm = self.read_rm(self.opsize, self.opsize / 8)
    if rm.raw_reg != 0 {
      return Err(invalid("0F 1F /reg != 0"))
    }
    return Ok(("nop", rm.text))
  }
  if op == 0x2E || op == 0x2F {
    let ptr = if self.has66 {
      8
    } else {
      4
    }
    let base = if op == 0x2E {
      "ucomis"
    } else {
      "comis"
    }
    let name = base + (if self.has66 {
      "d"
    } else {
      "s"
    })
    let rm = self.read_rm(128, ptr)
    return Ok((name, gpr_name(128, rm.reg, self.has_rex) + ", " + rm.text))
  }
  if op >= 0x40 && op <= 0x4F {
    let rm = self.read_rm(self.opsize, self.opsize / 8)
    return Ok((
      "cmov" + cc_names[op - 0x40],
      gpr_name(self.opsize, rm.reg, self.has_rex) + ", " + rm.text,
    ))
  }
  if op == 0x54 || op == 0x55 || op == 0x56 || op == 0x57 {
    if self.rep != 0 {
      return Err(invalid("0F 54-57 with F2/F3"))
    }
    let base = match op {
      0x54 => "and"
      0x55 => "andn"
      0x56 => "or"
      _ => "xor"
    }
    let name = base + (if self.has66 {
      "pd"
    } else {
      "ps"
    })
    let rm = self.read_rm(128, 16)
    return Ok((name, gpr_name(128, rm.reg, self.has_rex) + ", " + rm.text))
  }
  if op == 0x58 || op == 0x59 || op == 0x5C || op == 0x5D || op == 0x5E || op == 0x5F {
    let base = match op {
      0x58 => "add"
      0x59 => "mul"
      0x5C => "sub"
      0x5D => "min"
      0x5E => "div"
      _ => "max"
    }
    let mut suffix = "ps"
    let mut ptr = 16
    if self.rep == 0xF3 {
      suffix = "ss"
      ptr = 4
    } else if self.rep == 0xF2 {
      suffix = "sd"
      ptr = 8
    } else if self.has66 {
      suffix = "pd"
    }
    let rm = self.read_rm(128, ptr)
    return Ok((
      base + suffix,
      gpr_name(128, rm.reg, self.has_rex) + ", " + rm.text,
    ))
  }
  if op == 0x6E {
    if self.has66 == false {
      return Err(invalid("MMX 0F 6E without 66"))
    }
    let ssz = if self.rex_w() {
      64
    } else {
      32
    }
    let rm = self.read_rm(ssz, ssz / 8)
    let name = if self.rex_w() {
      "movq"
    } else {
      "movd"
    }
    return Ok((name, gpr_name(128, rm.reg, self.has_rex) + ", " + rm.text))
  }
  if op == 0x7E {
    if self.rep == 0xF3 {
      let rm = self.read_rm(64, 8)
      return Ok(("movq", gpr_name(128, rm.reg, self.has_rex) + ", " + rm.text))
    }
    if self.has66 == false {
      return Err(invalid("MMX 0F 7E without 66"))
    }
    let dsz = if self.rex_w() {
      64
    } else {
      32
    }
    let rm = self.read_rm(dsz, dsz / 8)
    let name = if self.rex_w() {
      "movq"
    } else {
      "movd"
    }
    return Ok((name, rm.text + ", " + gpr_name(128, rm.reg, self.has_rex)))
  }
  if op == 0x6F || op == 0x7F {
    let name = if self.has66 {
      "movdqa"
    } else if self.rep == 0xF3 {
      "movdqu"
    } else {
      return Err(invalid("MMX 0F 6F/7F without prefix"))
    }
    let rm = self.read_rm(128, 16)
    let xmm = gpr_name(128, rm.reg, self.has_rex)
    if op == 0x6F {
      return Ok((name, xmm + ", " + rm.text))
    }
    return Ok((name, rm.text + ", " + xmm))
  }
  if op == 0xD6 {
    if self.has66 == false {
      return Err(invalid("0F D6 without 66"))
    }
    let rm = self.read_rm(64, 8)
    return Ok(("movq", rm.text + ", " + gpr_name(128, rm.reg, self.has_rex)))
  }
  if op >= 0x80 && op <= 0x8F {
    let rel = sext32(self.u32())
    return Ok(("j" + cc_names[op - 0x80], self.target(rel)))
  }
  if op >= 0x90 && op <= 0x9F {
    let rm = self.read_rm(8, 1)
    return Ok(("set" + cc_names[op - 0x90], rm.text))
  }
  if op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB {
    let name = match op {
      0xA3 => "bt"
      0xAB => "bts"
      0xB3 => "btr"
      _ => "btc"
    }
    let rm = self.read_rm(self.opsize, self.opsize / 8)
    return Ok((name, rm.text + ", " + gpr_name(self.opsize, rm.reg, self.has_rex)))
  }
  if op == 0xAF {
    let rm = self.read_rm(self.opsize, self.opsize / 8)
    return Ok((
      "imul",
      gpr_name(self.opsize, rm.reg, self.has_rex) + ", " + rm.text,
    ))
  }
  if op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF {
    let ssz = if (op & 1) == 0 {
      1
    } else {
      2
    }
    let name = if op < 0xB8 {
      "movzx"
    } else {
      "movsx"
    }
    let rm = self.read_rm(ssz, ssz)
    return Ok((
      name,
      gpr_name(self.opsize, rm.reg, self.has_rex) + ", " + rm.text,
    ))
  }
  if op == 0xBA {
    let rm = self.read_rm(self.opsize, self.opsize / 8)
    if rm.raw_reg < 4 {
      return Err(invalid("0F BA /reg < 4"))
    }
    let name = match rm.raw_reg {
      4 => "bt"
      5 => "bts"
      6 => "btr"
      _ => "btc"
    }
    let imm = self.u8()
    return Ok((name, rm.text + ", " + hex_u64(imm.to_int64())))
  }
  if op == 0xC0 || op == 0xC1 {
    let sz = if op == 0xC0 {
      8
    } else {
      self.opsize
    }
    let rm = self.read_rm(sz, sz / 8)
    return Ok(("xadd", rm.text + ", " + gpr_name(sz, rm.reg, self.has_rex)))
  }
  if op >= 0xC8 && op <= 0xCF {
    let reg = (op - 0xC8) | (self.rex_b() << 3)
    return Ok(("bswap", gpr_name(self.opsize, reg, self.has_rex)))
  }
  if op == 0xDB || op == 0xDF || op == 0xEB || op == 0xEF {
    if self.has66 == false {
      return Err(invalid("MMX logical without 66"))
    }
    let name = match op {
      0xDB => "pand"
      0xDF => "pandn"
      0xEB => "por"
      _ => "pxor"
    }
    let rm = self.read_rm(128, 16)
    return Ok((name, gpr_name(128, rm.reg, self.has_rex) + ", " + rm.text))
  }
  if op == 0xAE {
    let raw = self.peek1()
    if raw == 0xE8 || raw == 0xF0 || raw == 0xF8 {
      let _ = self.r.skip(1)
      let name = if raw == 0xE8 {
        "lfence"
      } else if raw == 0xF0 {
        "mfence"
      } else {
        "sfence"
      }
      return Ok((name, ""))
    }
    let rm = self.read_rm(32, 4)
    if rm.is_mem == false {
      return Err(invalid("0F AE register form"))
    }
    if rm.raw_reg == 2 {
      return Ok(("ldmxcsr", rm.text))
    }
    if rm.raw_reg == 3 {
      return Ok(("stmxcsr", rm.text))
    }
    return Err(invalid("0F AE /reg"))
  }
  Err(invalid("unsupported two-byte opcode"))
}