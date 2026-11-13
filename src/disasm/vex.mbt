/// VEX (C4/C5) AVX subset, map 1 (0F). Operand text follows capstone 5.
/// Legacy 66/F2/F3 before VEX are ignored (pp comes from the VEX payload);
/// a REX prefix before VEX is refused.

fn Dec::vex(self : Dec, first : Int) -> Result[(String, String), @core.ParseError] {
  if self.has_rex {
    return Err(invalid("REX before VEX"))
  }
  let mut map = 1
  let mut pp = 0
  let mut vvvv = 0
  let mut vl = 0
  let mut vr = 0
  let mut vx = 0
  let mut vb = 0
  let mut vw = 0
  if first == 0xC5 {
    let p = self.u8()
    vr = ((-p - 1) >> 7) & 1
    vvvv = ((-p - 1) >> 3) & 0xF
    vl = (p >> 2) & 1
    pp = p & 3
  } else {
    let p1 = self.u8()
    vr = ((-p1 - 1) >> 7) & 1
    vx = ((-p1 - 1) >> 6) & 1
    vb = ((-p1 - 1) >> 5) & 1
    map = p1 & 0x1F
    let p2 = self.u8()
    vw = (p2 >> 7) & 1
    vvvv = ((-p2 - 1) >> 3) & 0xF
    vl = (p2 >> 2) & 1
    pp = p2 & 3
  }
  if map != 1 {
    return Err(invalid("VEX map outside subset"))
  }
  self.rex = (vw << 3) | (vr << 2) | (vx << 1) | vb
  self.has_rex = true
  self.opsize = if vw == 1 { 64 } else { 32 }
  let vs = if vl == 1 { 256 } else { 128 }
  let sfx = match pp {
    0 => "ps"
    1 => "pd"
    2 => "ss"
    _ => "sd"
  }
  let vname = gpr_name(vs, vvvv, true)
  let op = self.u8()

  // three-operand: dest, vvvv, r/m
  fn three(rm : RM) -> String {
    gpr_name(vs, rm.reg, true) + ", " + vname + ", " + rm.text
  }
  fn two(rm : RM) -> String {
    gpr_name(vs, rm.reg, true) + ", " + rm.text
  }
  fn store(rm : RM) -> String {
    rm.text + ", " + gpr_name(vs, rm.reg, true)
  }

  match op {
    0x77 => Ok((if vl == 1 { "vzeroall" } else { "vzeroupper" }, ""))
    0x58 => Ok(("vadd" + sfx, three(self.read_rm(vs, vs / 8))))
    0x59 => Ok(("vmul" + sfx, three(self.read_rm(vs, vs / 8))))
    0x5C => Ok(("vsub" + sfx, three(self.read_rm(vs, vs / 8))))
    0x5E => Ok(("vdiv" + sfx, three(self.read_rm(vs, vs / 8))))
    0x57 => Ok(("vxor" + (if pp == 1 { "pd" } else { "ps" }), three(self.read_rm(vs, vs / 8))))
    0x54 => Ok(("vand" + (if pp == 1 { "pd" } else { "ps" }), three(self.read_rm(vs, vs / 8))))
    0x56 => Ok(("vor" + (if pp == 1 { "pd" } else { "ps" }), three(self.read_rm(vs, vs / 8))))
    0x28 => Ok(("vmovap" + (if pp == 1 { "d" } else { "s" }), two(self.read_rm(vs, vs / 8))))
    0x29 => Ok(("vmovap" + (if pp == 1 { "d" } else { "s" }), store(self.read_rm(vs, vs / 8))))
    0x6F => {
      if pp == 1 { Ok(("vmovdqa", two(self.read_rm(vs, vs / 8)))) }
      else if pp == 2 { Ok(("vmovdqu", two(self.read_rm(vs, vs / 8)))) }
      else { Err(invalid("vmovdqa without 66")) }
    }
    0x7F => {
      if pp == 1 { Ok(("vmovdqa", store(self.read_rm(vs, vs / 8)))) }
      else if pp == 2 { Ok(("vmovdqu", store(self.read_rm(vs, vs / 8)))) }
      else { Err(invalid("vmovdqa store without 66")) }
    }
    0xEF => Ok(("vpxor", three(self.read_rm(vs, vs / 8))))
    0xDB => Ok(("vpand", three(self.read_rm(vs, vs / 8))))
    0xEB => Ok(("vpor", three(self.read_rm(vs, vs / 8))))
    0x10 => {
      let rm = self.read_rm(vs, if pp == 2 { 4 } else { 8 })
      let mn = "vmov" + (if pp == 2 { "ss" } else { "sd" })
      if rm.is_mem { Ok((mn, two(rm))) } else { Ok((mn, three(rm))) }
    }
    0x11 => {
      let rm = self.read_rm(vs, if pp == 2 { 4 } else { 8 })
      Ok(("vmov" + (if pp == 2 { "ss" } else { "sd" }), store(rm)))
    }
    0xC2 => {
      let rm = self.read_rm(vs, vs / 8)
      let imm = self.u8()
      Ok(("vcmp" + cmp_pred[imm & 31] + sfx, three(rm)))
    }
    0xC6 => {
      let rm = self.read_rm(vs, vs / 8)
      let imm = self.u8()
      Ok(("vshuf" + (if pp == 1 { "pd" } else { "ps" }), three(rm) + ", " + imm.to_string()))
    }
    0x70 => {
      let rm = self.read_rm(vs, vs / 8)
      let imm = self.u8()
      Ok(("vpshufd", gpr_name(vs, rm.reg, true) + ", " + rm.text + ", " + imm.to_string()))
    }
    0x71 | 0x72 | 0x73 => {
      let rm = self.read_rm(vs, vs / 8)
      let reg = rm.raw_reg
      let name = match (op, reg) {
        (0x71, 2) => "vpsrlw"
        (0x71, 4) => "vpsraw"
        (0x71, 6) => "vpsllw"
        (0x72, 2) => "vpsrld"
        (0x72, 4) => "vpsrad"
        (0x72, 6) => "vpslld"
        (0x73, 2) => "vpsrlq"
        (0x73, 6) => "vpsllq"
        (0x73, 3) => "vpsrldq"
        (0x73, 7) => "vpslldq"
        _ => ""
      }
      if name == "" { return Err(invalid("VEX shift group")) }
      let imm = self.u8()
      Ok((name, vname + ", " + rm.text + ", " + imm.to_string()))
    }
    0xC4 => {
      let rm = self.read_rm(32, 2)
      let imm = self.u8()
      Ok(("vpinsrw", gpr_name(vs, rm.reg, true) + ", " + vname + ", " + rm.text + ", " + imm.to_string()))
    }
    0xC5 => {
      let rm = self.read_rm(128, 2)
      let imm = self.u8()
      Ok(("vpextrw", gpr_name(32, rm.reg, true) + ", " + rm.text + ", " + imm.to_string()))
    }
    0x5B => Ok(("vcvtdq2ps", two(self.read_rm(vs, vs / 8))))
    0xE6 => {
      if pp == 2 { Ok(("vcvtdq2pd", two(self.read_rm(vs, 8)))) }
      else if pp == 3 { Ok(("vcvtpd2dq", two(self.read_rm(vs, vs / 8)))) }
      else { Err(invalid("0F E6 without pp")) }
    }
    0x2E => Ok(("vucomi" + (if pp == 1 { "sd" } else { "ss" }), two(self.read_rm(vs, if pp == 1 { 8 } else { 4 }))))
    0x6E => {
      let rm = self.read_rm(if vw == 1 { 64 } else { 32 }, if vw == 1 { 8 } else { 4 })
      Ok((if pp == 3 { "vmovq" } else { "vmovd" }, gpr_name(vs, rm.reg, true) + ", " + rm.text))
    }
    0x7E => {
      let rm = self.read_rm(if pp == 1 { 32 } else { 64 }, if pp == 1 { 4 } else { 8 })
      Ok((if pp == 1 { "vmovd" } else { "vmovq" }, rm.text + ", " + gpr_name(vs, rm.reg, true)))
    }
    0x50 => {
      let rm = self.read_rm(vs, 0)
      Ok(("vmovmsk" + (if pp == 1 { "pd" } else { "ps" }), gpr_name(32, rm.reg, true) + ", " + rm.text))
    }
    0x51 => Ok(("vsqrt" + (if pp == 1 { "pd" } else { "ps" }), two(self.read_rm(vs, vs / 8))))
    0xAE => {
      let rm = self.read_rm(32, 4)
      if rm.raw_reg == 2 { Ok(("vldmxcsr", rm.text)) }
      else if rm.raw_reg == 3 { Ok(("vstmxcsr", rm.text)) }
      else { Err(invalid("VEX AE group")) }
    }
    _ => Err(invalid("VEX opcode outside subset"))
  }
}