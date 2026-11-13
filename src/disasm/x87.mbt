/// x87 FPU (opcodes D8-DF) with ModR/M: memory forms and st(i) register forms.
///
/// Tables below are generated from capstone 5.0.7 so mnemonic + length agree
/// exactly (including capstone's undocumented forms and its D9 F0/F1 mapping
/// of f2xm1/fyl2x). REX.W is ignored by x87; REX.B extends memory base/index
/// but NOT the st(i) register index (only 8 FPU registers exist).

fn Dec::x87(self : Dec, op : Int) -> Result[(String, String), @core.ParseError] {
  let m = self.peek1()
  let mod = (m >> 6) & 3
  let oi = op - 0xD8
  if mod == 3 {
    let _ = self.u8()
    let idx = oi * 64 + (m & 0x3F)
    let name = x87_reg_name[idx]
    if name == "" {
      return Err(invalid("x87 register form"))
    }
    let st = "st(" + (m & 7).to_string() + ")"
    let ops = match x87_reg_form[idx] {
      2 => st
      3 => "st(0), " + st
      4 => st + ", st(0)"
      5 => "ax"
      _ => ""
    }
    return Ok((name, ops))
  }
  let reg = (m >> 3) & 7
  let mi = oi * 8 + reg
  let name = x87_mem_name[mi]
  if name == "" {
    return Err(invalid("x87 memory form"))
  }
  let rm = self.read_rm(32, x87_mem_ptr[mi])
  Ok((name, rm.text))
}

// x87 tables generated from capstone 5.0.7 (Cs CS_ARCH_X86 CS_MODE_64).
// reg index = (op-0xD8)*64 + (modrm & 0x3F); mem index = (op-0xD8)*8 + reg.
// form: 0=invalid 1=none 2=st(i) 3=st(0),st(i) 4=st(i),st(0) 5=ax

let x87_reg_name : Array[String] = [
  "fadd", "fadd", "fadd", "fadd", "fadd", "fadd",
  "fadd", "fadd", "fmul", "fmul", "fmul", "fmul",
  "fmul", "fmul", "fmul", "fmul", "fcom", "fcom",
  "fcom", "fcom", "fcom", "fcom", "fcom", "fcom",
  "fcomp", "fcomp", "fcomp", "fcomp", "fcomp", "fcomp",
  "fcomp", "fcomp", "fsub", "fsub", "fsub", "fsub",
  "fsub", "fsub", "fsub", "fsub", "fsubr", "fsubr",
  "fsubr", "fsubr", "fsubr", "fsubr", "fsubr", "fsubr",
  "fdiv", "fdiv", "fdiv", "fdiv", "fdiv", "fdiv",
  "fdiv", "fdiv", "fdivr", "fdivr", "fdivr", "fdivr",
  "fdivr", "fdivr", "fdivr", "fdivr", "fld", "fld",
  "fld", "fld", "fld", "fld", "fld", "fld",
  "fxch", "fxch", "fxch", "fxch", "fxch", "fxch",
  "fxch", "fxch", "fnop", "", "", "",
  "", "", "", "", "fstpnce", "fstpnce",
  "fstpnce", "fstpnce", "fstpnce", "fstpnce", "fstpnce", "fstpnce",
  "fchs", "fabs", "", "", "ftst", "fxam",
  "", "", "fld1", "fldl2t", "fldl2e", "fldpi",
  "fldlg2", "fldln2", "fldz", "", "f2xm1", "fyl2x",
  "fptan", "fpatan", "fxtract", "fprem1", "fdecstp", "fincstp",
  "fprem", "fyl2xp1", "fsqrt", "fsincos", "frndint", "fscale",
  "fsin", "fcos", "fcmovb", "fcmovb", "fcmovb", "fcmovb",
  "fcmovb", "fcmovb", "fcmovb", "fcmovb", "fcmove", "fcmove",
  "fcmove", "fcmove", "fcmove", "fcmove", "fcmove", "fcmove",
  "fcmovbe", "fcmovbe", "fcmovbe", "fcmovbe", "fcmovbe", "fcmovbe",
  "fcmovbe", "fcmovbe", "fcmovu", "fcmovu", "fcmovu", "fcmovu",
  "fcmovu", "fcmovu", "fcmovu", "fcmovu", "", "",
  "", "", "", "", "", "",
  "", "fucompp", "", "", "", "",
  "", "", "", "", "", "",
  "", "", "", "", "", "",
  "", "", "", "", "", "",
  "fcmovnb", "fcmovnb", "fcmovnb", "fcmovnb", "fcmovnb", "fcmovnb",
  "fcmovnb", "fcmovnb", "fcmovne", "fcmovne", "fcmovne", "fcmovne",
  "fcmovne", "fcmovne", "fcmovne", "fcmovne", "fcmovnbe", "fcmovnbe",
  "fcmovnbe", "fcmovnbe", "fcmovnbe", "fcmovnbe", "fcmovnbe", "fcmovnbe",
  "fcmovnu", "fcmovnu", "fcmovnu", "fcmovnu", "fcmovnu", "fcmovnu",
  "fcmovnu", "fcmovnu", "feni8087_nop", "fdisi8087_nop", "fnclex", "fninit",
  "fsetpm", "", "", "", "fucomi", "fucomi",
  "fucomi", "fucomi", "fucomi", "fucomi", "fucomi", "fucomi",
  "fcomi", "fcomi", "fcomi", "fcomi", "fcomi", "fcomi",
  "fcomi", "fcomi", "", "", "", "",
  "", "", "", "", "fadd", "fadd",
  "fadd", "fadd", "fadd", "fadd", "fadd", "fadd",
  "fmul", "fmul", "fmul", "fmul", "fmul", "fmul",
  "fmul", "fmul", "", "", "", "",
  "", "", "", "", "", "",
  "", "", "", "", "", "",
  "fsubr", "fsubr", "fsubr", "fsubr", "fsubr", "fsubr",
  "fsubr", "fsubr", "fsub", "fsub", "fsub", "fsub",
  "fsub", "fsub", "fsub", "fsub", "fdivr", "fdivr",
  "fdivr", "fdivr", "fdivr", "fdivr", "fdivr", "fdivr",
  "fdiv", "fdiv", "fdiv", "fdiv", "fdiv", "fdiv",
  "fdiv", "fdiv", "ffree", "ffree", "ffree", "ffree",
  "ffree", "ffree", "ffree", "ffree", "", "",
  "", "", "", "", "", "",
  "fst", "fst", "fst", "fst", "fst", "fst",
  "fst", "fst", "fstp", "fstp", "fstp", "fstp",
  "fstp", "fstp", "fstp", "fstp", "fucom", "fucom",
  "fucom", "fucom", "fucom", "fucom", "fucom", "fucom",
  "fucomp", "fucomp", "fucomp", "fucomp", "fucomp", "fucomp",
  "fucomp", "fucomp", "", "", "", "",
  "", "", "", "", "", "",
  "", "", "", "", "", "",
  "faddp", "faddp", "faddp", "faddp", "faddp", "faddp",
  "faddp", "faddp", "fmulp", "fmulp", "fmulp", "fmulp",
  "fmulp", "fmulp", "fmulp", "fmulp", "", "",
  "", "", "", "", "", "",
  "", "fcompp", "", "", "", "",
  "", "", "fsubrp", "fsubrp", "fsubrp", "fsubrp",
  "fsubrp", "fsubrp", "fsubrp", "fsubrp", "fsubp", "fsubp",
  "fsubp", "fsubp", "fsubp", "fsubp", "fsubp", "fsubp",
  "fdivrp", "fdivrp", "fdivrp", "fdivrp", "fdivrp", "fdivrp",
  "fdivrp", "fdivrp", "fdivp", "fdivp", "fdivp", "fdivp",
  "fdivp", "fdivp", "fdivp", "fdivp", "ffreep", "ffreep",
  "ffreep", "ffreep", "ffreep", "ffreep", "ffreep", "ffreep",
  "", "", "", "", "", "",
  "", "", "", "", "", "",
  "", "", "", "", "", "",
  "", "", "", "", "", "",
  "fnstsw", "", "", "", "", "",
  "", "", "fucompi", "fucompi", "fucompi", "fucompi",
  "fucompi", "fucompi", "fucompi", "fucompi", "fcompi", "fcompi",
  "fcompi", "fcompi", "fcompi", "fcompi", "fcompi", "fcompi",
  "", "", "", "", "", "",
  "", "",
]

let x87_reg_form : Array[Int] = [
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  1, 0, 0, 0, 0, 0, 0, 0, 3, 4, 4, 4, 4, 4, 4, 4,
  1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  1, 1, 1, 1, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
  3, 4, 4, 4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  3, 4, 4, 4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4,
  3, 4, 4, 4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4,
  2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  5, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
]

let x87_mem_name : Array[String] = [
  "fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr",
  "fdiv", "fdivr", "fld", "", "fst", "fstp",
  "fldenv", "fldcw", "fnstenv", "fnstcw", "fiadd", "fimul",
  "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr",
  "fild", "fisttp", "fist", "fistp", "", "fld",
  "", "fstp", "fadd", "fmul", "fcom", "fcomp",
  "fsub", "fsubr", "fdiv", "fdivr", "fld", "fisttp",
  "fst", "fstp", "frstor", "", "fnsave", "fnstsw",
  "fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr",
  "fidiv", "fidivr", "fild", "fisttp", "fist", "fistp",
  "fbld", "fild", "fbstp", "fistp",
]

let x87_mem_ptr : Array[Int] = [
  4, 4, 4, 4, 4, 4, 4, 4, 4, 0, 4, 4, 0, 2, 0, 2,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 0, 10, 0, 10,
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 4, 0, 4, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 10, 8, 10, 8,
]