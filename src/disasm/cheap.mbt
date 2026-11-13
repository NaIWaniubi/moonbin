/// Fallback decoders for the remaining common one-byte and 0F opcodes.
/// Reached only when the main dispatch did not handle the opcode, so these
/// never shadow existing branches. Operand text follows capstone 5.

fn Dec::cheap_one(self : Dec, op : Int) -> Result[(String, String), @core.ParseError] {
  match op {
    0xD7 => Ok(("xlatb", ""))
    0x9E => Ok(("sahf", ""))
    0x9F => Ok(("lahf", ""))
    0xF1 => Ok(("int1", ""))
    0xC8 => {
      let a = self.u16()
      let b = self.u8()
      Ok(("enter", hex_u64(a) + ", " + hex_u64(b.to_int64())))
    }
    0xCB => Ok(("retf", ""))
    0xCA => Ok(("retf", hex_u64(self.u16())))
    0xCF => Ok((if self.rex_w() { "iretq" } else { "iretd" }, ""))
    0xE0 | 0xE1 | 0xE2 | 0xE3 => {
      let rel = self.i8().to_int64()
      let name = match op {
        0xE0 => "loopne"
        0xE1 => "loope"
        0xE2 => "loop"
        _ => if self.addrsize == 32 { "jecxz" } else { "jrcxz" }
      }
      Ok((name, self.target(rel)))
    }
    0xE4 => Ok(("in", "al, " + hex_u64(self.u8().to_int64())))
    0xE5 => Ok(("in", (if self.opsize == 16 { "ax" } else { "eax" }) + ", " + hex_u64(self.u8().to_int64())))
    0xE6 => Ok(("out", hex_u64(self.u8().to_int64()) + ", al"))
    0xE7 => Ok(("out", hex_u64(self.u8().to_int64()) + ", " + (if self.opsize == 16 { "ax" } else { "eax" })))
    0xEC => Ok(("in", "al, dx"))
    0xED => Ok(("in", (if self.opsize == 16 { "ax" } else { "eax" }) + ", dx"))
    0xEE => Ok(("out", "dx, al"))
    0xEF => Ok(("out", "dx, " + (if self.opsize == 16 { "ax" } else { "eax" })))
    0xA0 | 0xA1 | 0xA2 | 0xA3 => {
      let addr = if self.addrsize == 64 { self.u64() } else { self.u32() }
      let wide = self.rex_w() || self.addrsize == 64
      let mn = if self.addrsize == 64 { "movabs" } else { "mov" }
      let reg = if wide { "rax" } else { "eax" }
      let ptr = ptr_text(if wide { 8 } else { 4 })
      let mem = ptr + "[" + hex_u64(addr) + "]"
      if op == 0xA0 || op == 0xA1 {
        Ok((mn, reg + ", " + mem))
      } else {
        Ok((mn, mem + ", " + reg))
      }
    }
    0xA4 | 0xA5 | 0xA6 | 0xA7 | 0xAA | 0xAB | 0xAC | 0xAD | 0xAE | 0xAF => {
      let base = match op {
        0xA4 | 0xA5 => "movs"
        0xA6 | 0xA7 => "cmps"
        0xAA | 0xAB => "stos"
        0xAC | 0xAD => "lods"
        _ => "scas"
      }
      let is_byte = (op & 1) == 0
      let suf = if is_byte {
        "b"
      } else if self.opsize == 64 {
        "q"
      } else if self.opsize == 16 {
        "w"
      } else {
        "d"
      }
      let is_cmp = base == "cmps" || base == "scas"
      let pre = if self.rep == 0xF3 {
        if is_cmp { "repe " } else { "rep " }
      } else if self.rep == 0xF2 {
        "repne "
      } else {
        ""
      }
      Ok((pre + base + suf, ""))
    }
    0x6C => Ok(("insb", ""))
    0x6D => Ok((if self.opsize == 16 { "insw" } else if self.opsize == 64 { "insq" } else { "insd" }, ""))
    0x6E => Ok(("outsb", ""))
    0x6F => Ok((if self.opsize == 16 { "outsw" } else if self.opsize == 64 { "outsq" } else { "outsd" }, ""))
    _ => Err(invalid("unsupported one-byte opcode"))
  }
}

fn Dec::cheap_two(self : Dec, op : Int) -> Result[(String, String), @core.ParseError] {
  if sse2_int_name[op] != "" {
    return self.sse2_int(op)
  }
  match op {
    0x31 => Ok(("rdtsc", ""))
    0xA2 => Ok(("cpuid", ""))
    0x35 => Ok(("sysexit", ""))
    0xB0 | 0xB1 => {
      let sz = if op == 0xB0 { 8 } else { self.opsize }
      let rm = self.read_rm(sz, sz / 8)
      Ok(("cmpxchg", rm.text + ", " + gpr_name(sz, rm.reg, self.has_rex)))
    }
    0xBC | 0xBD => {
      let rm = self.read_rm(self.opsize, self.opsize / 8)
      let name = if op == 0xBC {
        if self.rep == 0xF3 { "tzcnt" } else { "bsf" }
      } else {
        if self.rep == 0xF3 { "lzcnt" } else { "bsr" }
      }
      Ok((name, gpr_name(self.opsize, rm.reg, self.has_rex) + ", " + rm.text))
    }
    0x00 => {
      let rm = self.read_rm(16, 2)
      let name = match rm.raw_reg {
        0 => "sldt"
        1 => "str"
        2 => "lldt"
        3 => "ltr"
        4 => "verr"
        5 => "verw"
        _ => ""
      }
      if name == "" { return Err(invalid("0F 00 group")) }
      Ok((name, rm.text))
    }
    0x01 => {
      let m = self.peek1()
      if ((m >> 6) & 3) == 3 && ((m >> 3) & 7) == 2 && (m & 7) == 0 {
        let _ = self.u8()
        return Ok(("xgetbv", ""))
      }
      if ((m >> 6) & 3) == 3 && ((m >> 3) & 7) == 3 && (m & 7) == 0 {
        let _ = self.u8()
        return Ok(("xsetbv", ""))
      }
      Err(invalid("0F 01 group"))
    }
    0x79 => {
      let rm = self.read_rm(64, 0)
      Ok(("vmwrite", gpr_name(64, rm.reg, self.has_rex) + ", " + rm.text))
    }
    0x73 => {
      let rm = self.read_rm(128, 16)
      let name = match rm.raw_reg {
        3 => "psrldq"
        7 => "pslldq"
        _ => ""
      }
      if name == "" { return Err(invalid("0F 73 group")) }
      let imm = self.u8()
      Ok((name, rm.text + ", " + imm.to_string()))
    }
    0x70 => {
      if self.has66 == false { return Err(invalid("pshufw MMX")) }
      let rm = self.read_rm(128, 16)
      let imm = self.u8()
      Ok(("pshufd", gpr_name(128, rm.reg, true) + ", " + rm.text + ", " + imm.to_string()))
    }
    0xE6 => {
      if self.rep == 0xF3 {
        let rm = self.read_rm(128, 8)
        Ok(("cvtdq2pd", gpr_name(128, rm.reg, true) + ", " + rm.text))
      } else {
        Err(invalid("0F E6 without F3"))
      }
    }
    0x2C => {
      let rm = self.read_rm(128, if self.rep == 0xF2 { 8 } else { 4 })
      let mn = if self.rep == 0xF2 { "cvttsd2si" } else { "cvttss2si" }
      Ok((mn, gpr_name(self.opsize, rm.reg, self.has_rex) + ", " + rm.text))
    }
    0x2A => {
      let rm = self.read_rm(32, 4)
      let mn = if self.rep == 0xF2 { "cvtsi2sd" } else { "cvtsi2ss" }
      Ok((mn, gpr_name(128, rm.reg, true) + ", " + rm.text))
    }
    0xC2 => {
      let rm = self.read_rm(128, 16)
      let imm = self.u8()
      let sfx = if self.has66 { "pd" } else if self.rep == 0xF3 { "ss" } else if self.rep == 0xF2 { "sd" } else { "ps" }
      Ok(("cmp" + cmp_pred[imm & 31] + sfx, gpr_name(128, rm.reg, true) + ", " + rm.text))
    }
    0x51 => {
      let rm = self.read_rm(128, 16)
      let sfx = if self.has66 { "pd" } else if self.rep == 0xF3 { "ss" } else if self.rep == 0xF2 { "sd" } else { "ps" }
      Ok(("sqrt" + sfx, gpr_name(128, rm.reg, true) + ", " + rm.text))
    }
    _ => Err(invalid("unsupported two-byte opcode"))
  }
}