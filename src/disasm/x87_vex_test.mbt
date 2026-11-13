// Slice 2 unit tests: x87 FPU (D8-DF), VEX/AVX (C4/C5), and cheap integer/SSE
// ops added from the capstone diff. Known-good encodings, exact lengths, and
// refusal paths. op_str follows capstone 5 text where asserted. Self-contained
// helpers (unique names) so this file is scope-independent.

fn xb(arr : Array[Int]) -> Bytes {
  Bytes::from_array(arr.map(fn(x) { x.to_byte() }))
}

fn xok(data : Bytes, addr : Int64) -> @disasm.Insn {
  match @disasm.decode(data, addr) {
    Ok(ins) => ins
    Err(_) => abort("decode refused a valid encoding")
  }
}

fn xinv(data : Bytes) -> Unit raise {
  match @disasm.decode(data, 0L) {
    Err(@core.ParseError::Invalid(_)) => ()
    Ok(ins) => {
      inspect(ins.mnemonic, content="expected Invalid refusal, but decoded:")
      assert_true(false)
    }
    Err(@core.ParseError::Truncated(_)) => abort("expected Invalid, got Truncated")
    Err(@core.ParseError::BadMagic(_)) => abort("expected Invalid, got BadMagic")
  }
}

fn xtrunc(data : Bytes) -> Unit raise {
  match @disasm.decode(data, 0L) {
    Err(@core.ParseError::Truncated(_)) => ()
    Ok(ins) => {
      inspect(ins.mnemonic, content="expected Truncated refusal, but decoded:")
      assert_true(false)
    }
    Err(@core.ParseError::Invalid(_)) => abort("expected Truncated, got Invalid")
    Err(@core.ParseError::BadMagic(_)) => abort("expected Truncated, got BadMagic")
  }
}

// ---------------------------------------------------------------- x87 memory

test "x87: fld/fst/fstp dword and qword memory" {
  let a = xok(xb([0xd9, 0x00]), 0L)
  assert_eq(a.mnemonic, "fld")
  assert_eq(a.len, 2)
  assert_eq(a.op_str, "dword ptr [rax]")
  let b = xok(xb([0xd9, 0x10]), 0L)
  assert_eq(b.mnemonic, "fst")
  assert_eq(b.op_str, "dword ptr [rax]")
  let c = xok(xb([0xd9, 0x18]), 0L)
  assert_eq(c.mnemonic, "fstp")
  assert_eq(c.op_str, "dword ptr [rax]")
  let d = xok(xb([0xdd, 0x00]), 0L)
  assert_eq(d.mnemonic, "fld")
  assert_eq(d.op_str, "qword ptr [rax]")
  let e = xok(xb([0xdd, 0x18]), 0L)
  assert_eq(e.mnemonic, "fstp")
  assert_eq(e.op_str, "qword ptr [rax]")
}

test "x87: fadd/fmul/fsub/fdiv dword and qword memory" {
  let a = xok(xb([0xd8, 0x00]), 0L)
  assert_eq(a.mnemonic, "fadd")
  assert_eq(a.op_str, "dword ptr [rax]")
  let b = xok(xb([0xd8, 0x08]), 0L)
  assert_eq(b.mnemonic, "fmul")
  let c = xok(xb([0xd8, 0x20]), 0L)
  assert_eq(c.mnemonic, "fsub")
  let d = xok(xb([0xd8, 0x30]), 0L)
  assert_eq(d.mnemonic, "fdiv")
  let e = xok(xb([0xdc, 0x00]), 0L)
  assert_eq(e.mnemonic, "fadd")
  assert_eq(e.op_str, "qword ptr [rax]")
  let f = xok(xb([0xdc, 0x38]), 0L)
  assert_eq(f.mnemonic, "fdivr")
}

test "x87: fild/fist/fistp integer memory (word/dword/qword)" {
  let a = xok(xb([0xdb, 0x00]), 0L)
  assert_eq(a.mnemonic, "fild")
  assert_eq(a.op_str, "dword ptr [rax]")
  let b = xok(xb([0xdb, 0x10]), 0L)
  assert_eq(b.mnemonic, "fist")
  let c = xok(xb([0xdb, 0x18]), 0L)
  assert_eq(c.mnemonic, "fistp")
  let d = xok(xb([0xdf, 0x00]), 0L)
  assert_eq(d.mnemonic, "fild")
  assert_eq(d.op_str, "word ptr [rax]")
  let e = xok(xb([0xdf, 0x28]), 0L)
  assert_eq(e.mnemonic, "fild")
  assert_eq(e.op_str, "qword ptr [rax]")
  let f = xok(xb([0xdf, 0x38]), 0L)
  assert_eq(f.mnemonic, "fistp")
  assert_eq(f.op_str, "qword ptr [rax]")
}

test "x87: fiadd/ficom word and dword, fld/fstp tbyte, fldcw/fnstcw" {
  let a = xok(xb([0xda, 0x00]), 0L)
  assert_eq(a.mnemonic, "fiadd")
  assert_eq(a.op_str, "dword ptr [rax]")
  let b = xok(xb([0xde, 0x10]), 0L)
  assert_eq(b.mnemonic, "ficom")
  assert_eq(b.op_str, "word ptr [rax]")
  let c = xok(xb([0xdb, 0x28]), 0L)
  assert_eq(c.mnemonic, "fld")
  assert_eq(c.len, 2)
  assert_eq(c.op_str, "tbyte ptr [rax]")
  let d = xok(xb([0xdb, 0x38]), 0L)
  assert_eq(d.mnemonic, "fstp")
  assert_eq(d.op_str, "tbyte ptr [rax]")
  let e = xok(xb([0xd9, 0x28]), 0L)
  assert_eq(e.mnemonic, "fldcw")
  assert_eq(e.op_str, "word ptr [rax]")
  let f = xok(xb([0xd9, 0x38]), 0L)
  assert_eq(f.mnemonic, "fnstcw")
  assert_eq(f.op_str, "word ptr [rax]")
  let g = xok(xb([0xdf, 0x20]), 0L)
  assert_eq(g.mnemonic, "fbld")
  assert_eq(g.op_str, "tbyte ptr [rax]")
  let h = xok(xb([0xdf, 0x30]), 0L)
  assert_eq(h.mnemonic, "fbstp")
}

test "x87: memory disp8 and REX.B base" {
  let a = xok(xb([0xd9, 0x40, 0x08]), 0L)
  assert_eq(a.mnemonic, "fld")
  assert_eq(a.len, 3)
  assert_eq(a.op_str, "dword ptr [rax+0x8]")
  let b = xok(xb([0x41, 0xd8, 0x00]), 0L)
  assert_eq(b.mnemonic, "fadd")
  assert_eq(b.len, 3)
  assert_eq(b.op_str, "dword ptr [r8]")
}

// ------------------------------------------------------------- x87 register

test "x87: fadd/fmul/fsub/fdiv st(i) register forms (D8)" {
  let a = xok(xb([0xd8, 0xc1]), 0L)
  assert_eq(a.mnemonic, "fadd")
  assert_eq(a.len, 2)
  assert_eq(a.op_str, "st(1)")
  let b = xok(xb([0xd8, 0xc9]), 0L)
  assert_eq(b.mnemonic, "fmul")
  assert_eq(b.op_str, "st(1)")
  let c = xok(xb([0xd8, 0xe1]), 0L)
  assert_eq(c.mnemonic, "fsub")
  let d = xok(xb([0xd8, 0xf1]), 0L)
  assert_eq(d.mnemonic, "fdiv")
  let e = xok(xb([0xd8, 0xd1]), 0L)
  assert_eq(e.mnemonic, "fcom")
  assert_eq(e.op_str, "st(1)")
  let f = xok(xb([0xd8, 0xd9]), 0L)
  assert_eq(f.mnemonic, "fcomp")
}

test "x87: fld/fxch st(i), DC reversed-operand forms" {
  let a = xok(xb([0xd9, 0xc1]), 0L)
  assert_eq(a.mnemonic, "fld")
  assert_eq(a.op_str, "st(1)")
  let b = xok(xb([0xd9, 0xc9]), 0L)
  assert_eq(b.mnemonic, "fxch")
  assert_eq(b.op_str, "st(1)")
  let c = xok(xb([0xdc, 0xc1]), 0L)
  assert_eq(c.mnemonic, "fadd")
  assert_eq(c.op_str, "st(1), st(0)")
  let d = xok(xb([0xdc, 0xe1]), 0L)
  assert_eq(d.mnemonic, "fsubr")
  assert_eq(d.op_str, "st(1), st(0)")
  let e = xok(xb([0xdc, 0xf9]), 0L)
  assert_eq(e.mnemonic, "fdiv")
  assert_eq(e.op_str, "st(1), st(0)")
}

test "x87: fst/fstp/fucom/fucomp/ffree st(i) (DD)" {
  let a = xok(xb([0xdd, 0xd1]), 0L)
  assert_eq(a.mnemonic, "fst")
  assert_eq(a.op_str, "st(1)")
  let b = xok(xb([0xdd, 0xd9]), 0L)
  assert_eq(b.mnemonic, "fstp")
  assert_eq(b.op_str, "st(1)")
  let c = xok(xb([0xdd, 0xe1]), 0L)
  assert_eq(c.mnemonic, "fucom")
  assert_eq(c.op_str, "st(1)")
  let d = xok(xb([0xdd, 0xe9]), 0L)
  assert_eq(d.mnemonic, "fucomp")
  let e = xok(xb([0xdd, 0xc1]), 0L)
  assert_eq(e.mnemonic, "ffree")
}

test "x87: faddp/fmulp/fsubp/fdivp st(i) (DE), fcompp" {
  let a = xok(xb([0xde, 0xc1]), 0L)
  assert_eq(a.mnemonic, "faddp")
  assert_eq(a.op_str, "st(1)")
  let b = xok(xb([0xde, 0xc9]), 0L)
  assert_eq(b.mnemonic, "fmulp")
  let c = xok(xb([0xde, 0xe9]), 0L)
  assert_eq(c.mnemonic, "fsubp")
  let d = xok(xb([0xde, 0xf9]), 0L)
  assert_eq(d.mnemonic, "fdivp")
  let e = xok(xb([0xde, 0xd9]), 0L)
  assert_eq(e.mnemonic, "fcompp")
  assert_eq(e.op_str, "")
}

test "x87: fcmovcc st(0),st(i) (DA/DB), fucompp" {
  let a = xok(xb([0xda, 0xc1]), 0L)
  assert_eq(a.mnemonic, "fcmovb")
  assert_eq(a.op_str, "st(0), st(1)")
  let b = xok(xb([0xda, 0xc9]), 0L)
  assert_eq(b.mnemonic, "fcmove")
  let c = xok(xb([0xdb, 0xc9]), 0L)
  assert_eq(c.mnemonic, "fcmovne")
  let d = xok(xb([0xdb, 0xc1]), 0L)
  assert_eq(d.mnemonic, "fcmovnb")
  let e = xok(xb([0xda, 0xe9]), 0L)
  assert_eq(e.mnemonic, "fucompp")
  assert_eq(e.op_str, "")
}

test "x87: fucomi/fcomi/fucompi/fcompi st(i) (DB/DF)" {
  let a = xok(xb([0xdb, 0xe9]), 0L)
  assert_eq(a.mnemonic, "fucomi")
  assert_eq(a.op_str, "st(1)")
  let b = xok(xb([0xdb, 0xf1]), 0L)
  assert_eq(b.mnemonic, "fcomi")
  let c = xok(xb([0xdf, 0xe9]), 0L)
  assert_eq(c.mnemonic, "fucompi")
  let d = xok(xb([0xdf, 0xf1]), 0L)
  assert_eq(d.mnemonic, "fcompi")
}

test "x87: no-operand constants and unary ops (D9)" {
  let cases : Array[(Array[Int], String)] = [
    ([0xd9, 0xe8], "fld1"),
    ([0xd9, 0xee], "fldz"),
    ([0xd9, 0xe0], "fchs"),
    ([0xd9, 0xe1], "fabs"),
    ([0xd9, 0xe4], "ftst"),
    ([0xd9, 0xe5], "fxam"),
    ([0xd9, 0xd0], "fnop"),
    ([0xd9, 0xe9], "fldl2t"),
    ([0xd9, 0xea], "fldl2e"),
    ([0xd9, 0xeb], "fldpi"),
    ([0xd9, 0xec], "fldlg2"),
    ([0xd9, 0xed], "fldln2"),
    ([0xd9, 0xf0], "f2xm1"),
    ([0xd9, 0xf1], "fyl2x"),
    ([0xd9, 0xf2], "fptan"),
    ([0xd9, 0xf3], "fpatan"),
    ([0xd9, 0xf4], "fxtract"),
    ([0xd9, 0xf5], "fprem1"),
    ([0xd9, 0xf6], "fdecstp"),
    ([0xd9, 0xf7], "fincstp"),
    ([0xd9, 0xf8], "fprem"),
    ([0xd9, 0xf9], "fyl2xp1"),
    ([0xd9, 0xfa], "fsqrt"),
    ([0xd9, 0xfb], "fsincos"),
    ([0xd9, 0xfc], "frndint"),
    ([0xd9, 0xfd], "fscale"),
    ([0xd9, 0xfe], "fsin"),
    ([0xd9, 0xff], "fcos"),
  ]
  for c in cases {
    let ins = xok(xb(c.0), 0L)
    assert_eq(ins.mnemonic, c.1)
    assert_eq(ins.len, 2)
    assert_eq(ins.op_str, "")
  }
}

test "x87: fnstsw ax, fnclex, fninit, fwait" {
  let a = xok(xb([0xdf, 0xe0]), 0L)
  assert_eq(a.mnemonic, "fnstsw")
  assert_eq(a.len, 2)
  assert_eq(a.op_str, "ax")
  let b = xok(xb([0xdb, 0xe2]), 0L)
  assert_eq(b.mnemonic, "fnclex")
  assert_eq(b.op_str, "")
  let c = xok(xb([0xdb, 0xe3]), 0L)
  assert_eq(c.mnemonic, "fninit")
  let d = xok(xb([0x9b]), 0L)
  assert_eq(d.mnemonic, "wait")
  assert_eq(d.len, 1)
  assert_eq(d.op_str, "")
}

test "x87: REX.B ignored on st(i) register index" {
  let a = xok(xb([0x41, 0xd9, 0xc1]), 0L)
  assert_eq(a.mnemonic, "fld")
  assert_eq(a.len, 3)
  assert_eq(a.op_str, "st(1)")
}

test "x87: invalid encodings refuse with Invalid" {
  xinv(xb([0xd9, 0x08]))       // D9 /1 memory: invalid
  xinv(xb([0xd9, 0xd1]))       // D9 D1 register: invalid
  xinv(xb([0xd9, 0xe2]))       // D9 E2: invalid
  xinv(xb([0xd9, 0xe6]))       // D9 E6: invalid (capstone 5 maps f2xm1 to F0)
  xinv(xb([0xd9, 0xe7]))       // D9 E7: invalid
  xinv(xb([0xda, 0xe0]))       // DA E0: invalid
  xinv(xb([0xdd, 0xc8]))       // DD C8: invalid
  xinv(xb([0xdf, 0xe1]))       // DF E1: invalid
}

test "x87: truncated encodings refuse with Truncated" {
  xtrunc(xb([0xd9]))           // opcode only
  xtrunc(xb([0xd8, 0x40]))     // mod=01 needs disp8
  xtrunc(xb([0xd9, 0x80, 0x00])) // mod=10 needs disp32
}

// ------------------------------------------------------------------ VEX/AVX

test "vex: vzeroupper / vzeroall (C5 F8/F C 77)" {
  let a = xok(xb([0xc5, 0xf8, 0x77]), 0L)
  assert_eq(a.mnemonic, "vzeroupper")
  assert_eq(a.len, 3)
  assert_eq(a.op_str, "")
  let b = xok(xb([0xc5, 0xfc, 0x77]), 0L)
  assert_eq(b.mnemonic, "vzeroall")
  assert_eq(b.len, 3)
}

test "vex: vaddps/vaddpd/vaddss/vaddsd 3-operand (C5)" {
  let a = xok(xb([0xc5, 0xf8, 0x58, 0xc1]), 0L)
  assert_eq(a.mnemonic, "vaddps")
  assert_eq(a.len, 4)
  assert_eq(a.op_str, "xmm0, xmm0, xmm1")
  let b = xok(xb([0xc5, 0xf9, 0x58, 0xc1]), 0L)
  assert_eq(b.mnemonic, "vaddpd")
  assert_eq(b.op_str, "xmm0, xmm0, xmm1")
  let c = xok(xb([0xc5, 0xfa, 0x58, 0xc1]), 0L)
  assert_eq(c.mnemonic, "vaddss")
  let d = xok(xb([0xc5, 0xfb, 0x58, 0xc1]), 0L)
  assert_eq(d.mnemonic, "vaddsd")
  let e = xok(xb([0xc5, 0xf0, 0x58, 0xc1]), 0L)
  assert_eq(e.mnemonic, "vaddps")
  assert_eq(e.op_str, "xmm0, xmm1, xmm1")
}

test "vex: vmovaps/vmovapd/vmovdqa/vmovdqu 2-operand" {
  let a = xok(xb([0xc5, 0xf8, 0x28, 0xc1]), 0L)
  assert_eq(a.mnemonic, "vmovaps")
  assert_eq(a.len, 4)
  assert_eq(a.op_str, "xmm0, xmm1")
  let b = xok(xb([0xc5, 0xf9, 0x28, 0xc1]), 0L)
  assert_eq(b.mnemonic, "vmovapd")
  let c = xok(xb([0xc5, 0xf9, 0x6f, 0xc1]), 0L)
  assert_eq(c.mnemonic, "vmovdqa")
  let d = xok(xb([0xc5, 0xfa, 0x6f, 0xc1]), 0L)
  assert_eq(d.mnemonic, "vmovdqu")
  let e = xok(xb([0xc5, 0xf8, 0x29, 0xc1]), 0L)
  assert_eq(e.mnemonic, "vmovaps")
  assert_eq(e.op_str, "xmm1, xmm0")
}

test "vex: vpxor/vpand/vpor/vxorps/vmulps" {
  let a = xok(xb([0xc5, 0xf9, 0xef, 0xc1]), 0L)
  assert_eq(a.mnemonic, "vpxor")
  assert_eq(a.op_str, "xmm0, xmm0, xmm1")
  let b = xok(xb([0xc5, 0xf9, 0xdb, 0xc1]), 0L)
  assert_eq(b.mnemonic, "vpand")
  let c = xok(xb([0xc5, 0xf9, 0xeb, 0xc1]), 0L)
  assert_eq(c.mnemonic, "vpor")
  let d = xok(xb([0xc5, 0xf8, 0x57, 0xc1]), 0L)
  assert_eq(d.mnemonic, "vxorps")
  let e = xok(xb([0xc5, 0xf8, 0x59, 0xc1]), 0L)
  assert_eq(e.mnemonic, "vmulps")
}

test "vex: vmovss/vmovsd load, store, and reg-reg" {
  let a = xok(xb([0xc5, 0xfa, 0x10, 0x01]), 0L)
  assert_eq(a.mnemonic, "vmovss")
  assert_eq(a.len, 4)
  assert_eq(a.op_str, "xmm0, dword ptr [rcx]")
  let b = xok(xb([0xc5, 0xfa, 0x11, 0x01]), 0L)
  assert_eq(b.mnemonic, "vmovss")
  assert_eq(b.op_str, "dword ptr [rcx], xmm0")
  let c = xok(xb([0xc5, 0xfa, 0x10, 0xc1]), 0L)
  assert_eq(c.mnemonic, "vmovss")
  assert_eq(c.op_str, "xmm0, xmm0, xmm1")
  let d = xok(xb([0xc5, 0xfb, 0x10, 0x01]), 0L)
  assert_eq(d.mnemonic, "vmovsd")
  assert_eq(d.op_str, "xmm0, qword ptr [rcx]")
}

test "vex: 256-bit ymm (L=1)" {
  let a = xok(xb([0xc5, 0xfc, 0x58, 0xc1]), 0L)
  assert_eq(a.mnemonic, "vaddps")
  assert_eq(a.op_str, "ymm0, ymm0, ymm1")
  let b = xok(xb([0xc5, 0xfc, 0x28, 0xc1]), 0L)
  assert_eq(b.mnemonic, "vmovaps")
  assert_eq(b.op_str, "ymm0, ymm1")
  let c = xok(xb([0xc5, 0xfd, 0x6f, 0xc1]), 0L)
  assert_eq(c.mnemonic, "vmovdqa")
  assert_eq(c.op_str, "ymm0, ymm1")
}

test "vex: 3-byte C4 prefix, map 1" {
  let a = xok(xb([0xc4, 0xe1, 0xf8, 0x58, 0xc1]), 0L)
  assert_eq(a.mnemonic, "vaddps")
  assert_eq(a.len, 5)
  assert_eq(a.op_str, "xmm0, xmm0, xmm1")
  let b = xok(xb([0xc4, 0xe1, 0xf9, 0x58, 0xc1]), 0L)
  assert_eq(b.mnemonic, "vaddpd")
  let c = xok(xb([0xc4, 0xe1, 0x7c, 0x58, 0xc1]), 0L)
  assert_eq(c.mnemonic, "vaddps")
  assert_eq(c.op_str, "ymm0, ymm0, ymm1")
  let d = xok(xb([0xc4, 0xe1, 0xf8, 0x77]), 0L)
  assert_eq(d.mnemonic, "vzeroupper")
  assert_eq(d.len, 4)
}

test "vex: REX.R/B extension via VEX bits" {
  let a = xok(xb([0xc5, 0x78, 0x58, 0xc1]), 0L)
  assert_eq(a.mnemonic, "vaddps")
  assert_eq(a.op_str, "xmm8, xmm0, xmm1")
  let b = xok(xb([0xc4, 0x61, 0x78, 0x28, 0xc1]), 0L)
  assert_eq(b.mnemonic, "vmovaps")
  assert_eq(b.op_str, "xmm8, xmm1")
}

test "vex: vcmp predicate-split mnemonic, vpshufd, vpsrlw" {
  let a = xok(xb([0xc5, 0xf8, 0xc2, 0xc1, 0x00]), 0L)
  assert_eq(a.mnemonic, "vcmpeqps")
  assert_eq(a.len, 5)
  assert_eq(a.op_str, "xmm0, xmm0, xmm1")
  let b = xok(xb([0xc5, 0xf8, 0xc2, 0xc1, 0x01]), 0L)
  assert_eq(b.mnemonic, "vcmpltps")
  let c = xok(xb([0xc5, 0xf9, 0x70, 0xc1, 0x00]), 0L)
  assert_eq(c.mnemonic, "vpshufd")
  assert_eq(c.op_str, "xmm0, xmm1, 0")
  let d = xok(xb([0xc5, 0xf9, 0x71, 0xd1, 0x04]), 0L)
  assert_eq(d.mnemonic, "vpsrlw")
  assert_eq(d.op_str, "xmm0, xmm1, 4")
}

test "vex: vpinsrw / vpextrw / vshufps / conversions" {
  let a = xok(xb([0xc5, 0xf9, 0xc4, 0xc1, 0x02]), 0L)
  assert_eq(a.mnemonic, "vpinsrw")
  assert_eq(a.len, 5)
  assert_eq(a.op_str, "xmm0, xmm0, ecx, 2")
  let b = xok(xb([0xc5, 0xf9, 0xc5, 0xc1, 0x02]), 0L)
  assert_eq(b.mnemonic, "vpextrw")
  assert_eq(b.op_str, "eax, xmm1, 2")
  let c = xok(xb([0xc5, 0xf8, 0xc6, 0xc1, 0x00]), 0L)
  assert_eq(c.mnemonic, "vshufps")
  assert_eq(c.op_str, "xmm0, xmm0, xmm1, 0")
  let d = xok(xb([0xc5, 0xf8, 0x5b, 0xc1]), 0L)
  assert_eq(d.mnemonic, "vcvtdq2ps")
  let e = xok(xb([0xc5, 0xfa, 0xe6, 0xc1]), 0L)
  assert_eq(e.mnemonic, "vcvtdq2pd")
  let f = xok(xb([0xc5, 0xf8, 0x2e, 0xc1]), 0L)
  assert_eq(f.mnemonic, "vucomiss")
}

test "vex: vmovd/vmovq, vmovmskps, vsqrtps, vldmxcsr" {
  let a = xok(xb([0xc5, 0xf9, 0x6e, 0xc1]), 0L)
  assert_eq(a.mnemonic, "vmovd")
  assert_eq(a.op_str, "xmm0, ecx")
  let b = xok(xb([0xc5, 0xf9, 0x7e, 0xc1]), 0L)
  assert_eq(b.mnemonic, "vmovd")
  assert_eq(b.op_str, "ecx, xmm0")
  let c = xok(xb([0xc5, 0xfa, 0x7e, 0xc1]), 0L)
  assert_eq(c.mnemonic, "vmovq")
  let d = xok(xb([0xc5, 0xf8, 0x50, 0xc1]), 0L)
  assert_eq(d.mnemonic, "vmovmskps")
  assert_eq(d.op_str, "eax, xmm1")
  let e = xok(xb([0xc5, 0xf8, 0x51, 0xc1]), 0L)
  assert_eq(e.mnemonic, "vsqrtps")
  let f = xok(xb([0xc5, 0xf8, 0xae, 0x11]), 0L)
  assert_eq(f.mnemonic, "vldmxcsr")
  assert_eq(f.op_str, "dword ptr [rcx]")
}

test "vex: legacy 66/F3 ignored, REX before VEX refused" {
  let a = xok(xb([0x66, 0xc5, 0xf8, 0x58, 0xc1]), 0L)
  assert_eq(a.mnemonic, "vaddps")
  assert_eq(a.len, 5)
  let b = xok(xb([0xf3, 0xc5, 0xf8, 0x58, 0xc1]), 0L)
  assert_eq(b.mnemonic, "vaddps")
  assert_eq(b.len, 5)
  xinv(xb([0x48, 0xc5, 0xf8, 0x58, 0xc1]))
}

test "vex: unsupported maps and forms refuse with Invalid" {
  xinv(xb([0xc4, 0xe2, 0x79, 0x00, 0xc1]))  // map 2 (0F38): outside subset
  xinv(xb([0xc4, 0xe3, 0x79, 0x0c, 0xc1, 0x00])) // map 3 (0F3A): outside subset
  xinv(xb([0xc5, 0xf8, 0x0b, 0xc1]))        // VEX ud2: invalid
  xinv(xb([0xc5, 0xf8, 0xc0, 0xc1, 0x00]))  // VEX xadd: invalid
  xinv(xb([0xc5, 0xf8, 0xe6, 0xc1]))        // 0F E6 without pp: invalid
}

test "vex: truncated prefixes refuse with Truncated" {
  xtrunc(xb([0xc5]))
  xtrunc(xb([0xc5, 0xf8]))
  xtrunc(xb([0xc4, 0xe1]))
  xtrunc(xb([0xc5, 0xf8, 0x58]))            // missing modrm
  xtrunc(xb([0xc5, 0xf8, 0x58, 0x40]))      // mod=01 needs disp8
}

// ------------------------------------------------------- cheap integer/SSE

test "cheap: pause / bsf / bsr / tzcnt / lzcnt / cmpxchg" {
  let a = xok(xb([0xf3, 0x90]), 0L)
  assert_eq(a.mnemonic, "pause")
  assert_eq(a.len, 2)
  let b = xok(xb([0x0f, 0xbc, 0xc1]), 0L)
  assert_eq(b.mnemonic, "bsf")
  assert_eq(b.op_str, "eax, ecx")
  let c = xok(xb([0x0f, 0xbd, 0xc1]), 0L)
  assert_eq(c.mnemonic, "bsr")
  let d = xok(xb([0xf3, 0x0f, 0xbc, 0xc1]), 0L)
  assert_eq(d.mnemonic, "tzcnt")
  let e = xok(xb([0xf3, 0x0f, 0xbd, 0xc1]), 0L)
  assert_eq(e.mnemonic, "lzcnt")
  let f = xok(xb([0x48, 0x0f, 0xb1, 0xc1]), 0L)
  assert_eq(f.mnemonic, "cmpxchg")
  assert_eq(f.len, 4)
  assert_eq(f.op_str, "rcx, rax")
}

test "cheap: xlatb / sahf / lahf / int1 / rdtsc / cpuid" {
  let a = xok(xb([0xd7]), 0L)
  assert_eq(a.mnemonic, "xlatb")
  assert_eq(a.len, 1)
  let b = xok(xb([0x9e]), 0L)
  assert_eq(b.mnemonic, "sahf")
  let c = xok(xb([0x9f]), 0L)
  assert_eq(c.mnemonic, "lahf")
  let d = xok(xb([0xf1]), 0L)
  assert_eq(d.mnemonic, "int1")
  let e = xok(xb([0x0f, 0x31]), 0L)
  assert_eq(e.mnemonic, "rdtsc")
  let f = xok(xb([0x0f, 0xa2]), 0L)
  assert_eq(f.mnemonic, "cpuid")
}

test "cheap: enter / retf / iretd / iretq / loop / jrcxz" {
  let a = xok(xb([0xc8, 0x01, 0x00, 0x00]), 0L)
  assert_eq(a.mnemonic, "enter")
  assert_eq(a.len, 4)
  let b = xok(xb([0xcb]), 0L)
  assert_eq(b.mnemonic, "retf")
  let c = xok(xb([0xca, 0x08, 0x00]), 0L)
  assert_eq(c.mnemonic, "retf")
  assert_eq(c.len, 3)
  let d = xok(xb([0xcf]), 0L)
  assert_eq(d.mnemonic, "iretd")
  let e = xok(xb([0x48, 0xcf]), 0L)
  assert_eq(e.mnemonic, "iretq")
  let f = xok(xb([0xe2, 0xfe]), 0x1000L)
  assert_eq(f.mnemonic, "loop")
  assert_eq(f.op_str, "0x1000")
  let g = xok(xb([0xe3, 0xfe]), 0x1000L)
  assert_eq(g.mnemonic, "jrcxz")
  let h = xok(xb([0x67, 0xe3, 0xfe]), 0x1000L)
  assert_eq(h.mnemonic, "jecxz")
}

test "cheap: in / out port I/O" {
  let a = xok(xb([0xe4, 0x01]), 0L)
  assert_eq(a.mnemonic, "in")
  assert_eq(a.len, 2)
  let b = xok(xb([0xe6, 0x01]), 0L)
  assert_eq(b.mnemonic, "out")
  let c = xok(xb([0xec]), 0L)
  assert_eq(c.mnemonic, "in")
  assert_eq(c.len, 1)
  let d = xok(xb([0xef]), 0L)
  assert_eq(d.mnemonic, "out")
}

test "cheap: string ops movs/stos/lods/scas/cmps with rep prefixes" {
  let a = xok(xb([0xa4]), 0L)
  assert_eq(a.mnemonic, "movsb")
  assert_eq(a.len, 1)
  let b = xok(xb([0xf3, 0xa5]), 0L)
  assert_eq(b.mnemonic, "rep movsd")
  assert_eq(b.len, 2)
  let c = xok(xb([0xf3, 0xa7]), 0L)
  assert_eq(c.mnemonic, "repe cmpsd")
  let d = xok(xb([0xf2, 0xa6]), 0L)
  assert_eq(d.mnemonic, "repne cmpsb")
  let e = xok(xb([0xf3, 0xaa]), 0L)
  assert_eq(e.mnemonic, "rep stosb")
  let f = xok(xb([0xf2, 0xaf]), 0L)
  assert_eq(f.mnemonic, "repne scasd")
  let g = xok(xb([0x48, 0xa5]), 0L)
  assert_eq(g.mnemonic, "movsq")
  let h = xok(xb([0x66, 0xa5]), 0L)
  assert_eq(h.mnemonic, "movsw")
  let i = xok(xb([0xac]), 0L)
  assert_eq(i.mnemonic, "lodsb")
  let j = xok(xb([0x6d]), 0L)
  assert_eq(j.mnemonic, "insd")
  let k = xok(xb([0x6f]), 0L)
  assert_eq(k.mnemonic, "outsd")
}

test "cheap: moffs mov A0-A3 (movabs for moffs64)" {
  let a = xok(xb([0x48, 0xa1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]), 0L)
  assert_eq(a.mnemonic, "movabs")
  assert_eq(a.len, 10)
  assert_eq(a.op_str, "rax, qword ptr [0x1122334455667788]")
  let b = xok(xb([0xa1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]), 0L)
  assert_eq(b.mnemonic, "movabs")
  assert_eq(b.len, 9)
  let c = xok(xb([0x67, 0xa1, 0x88, 0x77, 0x66, 0x55]), 0L)
  assert_eq(c.mnemonic, "mov")
  assert_eq(c.len, 6)
  let d = xok(xb([0x48, 0xa3, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]), 0L)
  assert_eq(d.mnemonic, "movabs")
  assert_eq(d.op_str, "qword ptr [0x1122334455667788], rax")
}

test "cheap: SSE2 integer paddq/psubb/pcmpgtb/pcmpeqb/pmuludq/psrldq" {
  let a = xok(xb([0x66, 0x0f, 0xd4, 0xc1]), 0L)
  assert_eq(a.mnemonic, "paddq")
  assert_eq(a.len, 4)
  assert_eq(a.op_str, "xmm0, xmm1")
  let b = xok(xb([0x66, 0x0f, 0xf8, 0xc1]), 0L)
  assert_eq(b.mnemonic, "psubb")
  let c = xok(xb([0x66, 0x0f, 0x64, 0xc1]), 0L)
  assert_eq(c.mnemonic, "pcmpgtb")
  let d = xok(xb([0x66, 0x0f, 0x74, 0xc1]), 0L)
  assert_eq(d.mnemonic, "pcmpeqb")
  let e = xok(xb([0x66, 0x0f, 0xf4, 0xc1]), 0L)
  assert_eq(e.mnemonic, "pmuludq")
  let f = xok(xb([0x66, 0x0f, 0x73, 0xd9, 0x04]), 0L)
  assert_eq(f.mnemonic, "psrldq")
  assert_eq(f.len, 5)
  assert_eq(f.op_str, "xmm1, 4")
}

test "cheap: SSE conversions cvtdq2pd/cvttsd2si/cvtsi2ss, cmpeqps, sqrtps" {
  let a = xok(xb([0xf3, 0x0f, 0xe6, 0xc1]), 0L)
  assert_eq(a.mnemonic, "cvtdq2pd")
  assert_eq(a.len, 4)
  let b = xok(xb([0xf2, 0x0f, 0x2c, 0xc1]), 0L)
  assert_eq(b.mnemonic, "cvttsd2si")
  assert_eq(b.op_str, "eax, xmm1")
  let c = xok(xb([0xf3, 0x0f, 0x2a, 0xc1]), 0L)
  assert_eq(c.mnemonic, "cvtsi2ss")
  assert_eq(c.op_str, "xmm0, ecx")
  let d = xok(xb([0x0f, 0xc2, 0xc1, 0x00]), 0L)
  assert_eq(d.mnemonic, "cmpeqps")
  assert_eq(d.op_str, "xmm0, xmm1")
  let e = xok(xb([0x0f, 0x51, 0xc1]), 0L)
  assert_eq(e.mnemonic, "sqrtps")
  let f = xok(xb([0x66, 0x0f, 0x70, 0xc1, 0x00]), 0L)
  assert_eq(f.mnemonic, "pshufd")
  assert_eq(f.op_str, "xmm0, xmm1, 0")
}

test "cheap: SSE2 integer without 66 refuses (MMX), ud2/prefetch stay Invalid" {
  xinv(xb([0x0f, 0xd4, 0xc1]))   // paddq without 66: MMX, refused
  xinv(xb([0x0f, 0x70, 0xc1, 0x00])) // pshufw MMX: refused
  xinv(xb([0x0f, 0x0b]))         // ud2: still outside subset
  xinv(xb([0x0f, 0x0d]))         // prefetch: still outside subset
}

test "cheap: sldt / str / xgetbv / sysexit / vmwrite" {
  let a = xok(xb([0x0f, 0x00, 0xc0]), 0L)
  assert_eq(a.mnemonic, "sldt")
  assert_eq(a.len, 3)
  let b = xok(xb([0x0f, 0x00, 0xc8]), 0L)
  assert_eq(b.mnemonic, "str")
  let c = xok(xb([0x0f, 0x01, 0xd0]), 0L)
  assert_eq(c.mnemonic, "xgetbv")
  assert_eq(c.len, 3)
  let d = xok(xb([0x0f, 0x35]), 0L)
  assert_eq(d.mnemonic, "sysexit")
  let e = xok(xb([0x0f, 0x79, 0xc1]), 0L)
  assert_eq(e.mnemonic, "vmwrite")
  assert_eq(e.op_str, "rax, rcx")
}