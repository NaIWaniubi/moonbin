// Hand-written unit tests: known-good encodings, exact lengths, refusal paths.
// op_str format is this package's own contract (capstone cross-check compares
// mnemonic + length only).

fn b(arr : Array[Int]) -> Bytes {
  Bytes::from_array(arr.map(fn(x) { x.to_byte() }))
}

fn ok(data : Bytes, addr : Int64) -> Insn {
  match decode(data, addr) {
    Ok(ins) => ins
    Err(_) => abort("decode refused a valid encoding")
  }
}

fn expect_invalid(data : Bytes) -> Unit raise {
  match decode(data, 0L) {
    Err(@core.ParseError::Invalid(_)) => ()
    Ok(ins) => {
      inspect(ins.mnemonic, content="expected Invalid refusal, but decoded:")
      assert_true(false)
    }
    Err(@core.ParseError::Truncated(_)) => abort("expected Invalid, got Truncated")
    Err(@core.ParseError::BadMagic(_)) => abort("expected Invalid, got BadMagic")
  }
}

fn expect_truncated(data : Bytes) -> Unit raise {
  match decode(data, 0L) {
    Err(@core.ParseError::Truncated(_)) => ()
    Ok(ins) => {
      inspect(ins.mnemonic, content="expected Truncated refusal, but decoded:")
      assert_true(false)
    }
    Err(@core.ParseError::Invalid(_)) => abort("expected Truncated, got Invalid")
    Err(@core.ParseError::BadMagic(_)) => abort("expected Truncated, got BadMagic")
  }
}

test "decode: mov rbp, rsp (48 89 e5)" {
  let ins = ok(b([0x48, 0x89, 0xe5]), 0x1000L)
  assert_eq(ins.mnemonic, "mov")
  assert_eq(ins.len, 3)
  assert_eq(ins.op_str, "rbp, rsp")
  assert_eq(ins.addr, 0x1000L)
  assert_eq(ins.bytes.length(), 3)
  assert_eq(ins.bytes[0].to_int(), 0x48)
}

test "decode: sub rsp, 0x20 (48 83 ec 20)" {
  let ins = ok(b([0x48, 0x83, 0xec, 0x20]), 0L)
  assert_eq(ins.mnemonic, "sub")
  assert_eq(ins.len, 4)
  assert_eq(ins.op_str, "rsp, 0x20")
}

test "decode: mov eax, 1 (b8 01 00 00 00)" {
  let ins = ok(b([0xb8, 0x01, 0x00, 0x00, 0x00]), 0L)
  assert_eq(ins.mnemonic, "mov")
  assert_eq(ins.len, 5)
  assert_eq(ins.op_str, "eax, 0x1")
}

test "decode: ret / nop / int3" {
  let r = ok(b([0xc3]), 0L)
  assert_eq(r.mnemonic, "ret")
  assert_eq(r.len, 1)
  assert_eq(r.op_str, "")
  let n = ok(b([0x90]), 0L)
  assert_eq(n.mnemonic, "nop")
  assert_eq(n.len, 1)
  let i = ok(b([0xcc]), 0L)
  assert_eq(i.mnemonic, "int3")
  assert_eq(i.len, 1)
}

test "decode: jz rel32 (0f 84) target = addr + len + rel" {
  let ins = ok(b([0x0f, 0x84, 0x10, 0x00, 0x00, 0x00]), 0x1000L)
  assert_eq(ins.mnemonic, "je")
  assert_eq(ins.len, 6)
  assert_eq(ins.op_str, "0x1016")
}

test "decode: jmp rel8 negative (eb fe)" {
  let ins = ok(b([0xeb, 0xfe]), 0x1000L)
  assert_eq(ins.mnemonic, "jmp")
  assert_eq(ins.len, 2)
  assert_eq(ins.op_str, "0x1000")
}

test "decode: mov rax, [rbp-8] (48 8b 45 f8)" {
  let ins = ok(b([0x48, 0x8b, 0x45, 0xf8]), 0L)
  assert_eq(ins.mnemonic, "mov")
  assert_eq(ins.len, 4)
  assert_eq(ins.op_str, "rax, qword ptr [rbp-0x8]")
}

test "decode: REX.R / REX.B register extension" {
  let m = ok(b([0x4c, 0x89, 0xc0]), 0L)
  assert_eq(m.mnemonic, "mov")
  assert_eq(m.len, 3)
  assert_eq(m.op_str, "rax, r8")
  let p = ok(b([0x41, 0x50]), 0L)
  assert_eq(p.mnemonic, "push")
  assert_eq(p.len, 2)
  assert_eq(p.op_str, "r8")
  let q = ok(b([0x41, 0x58]), 0L)
  assert_eq(q.mnemonic, "pop")
  assert_eq(q.op_str, "r8")
}

test "decode: 66 operand-size prefix" {
  let m = ok(b([0x66, 0xb8, 0x01, 0x00]), 0L)
  assert_eq(m.mnemonic, "mov")
  assert_eq(m.len, 4)
  assert_eq(m.op_str, "ax, 0x1")
  let s = ok(b([0x66, 0x89, 0x00]), 0L)
  assert_eq(s.len, 3)
  assert_eq(s.op_str, "word ptr [rax], ax")
}

test "decode: movabs r64, imm64 (48 b8)" {
  let ins = ok(
    b([0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]),
    0L,
  )
  assert_eq(ins.mnemonic, "movabs")
  assert_eq(ins.len, 10)
  assert_eq(ins.op_str, "rax, 0x1122334455667788")
}

test "decode: SIB no-base absolute and scaled index" {
  let a = ok(b([0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00]), 0L)
  assert_eq(a.mnemonic, "mov")
  assert_eq(a.len, 8)
  assert_eq(a.op_str, "rax, qword ptr [0x0]")
  let s = ok(b([0x48, 0x8b, 0x44, 0x8d, 0x00]), 0L)
  assert_eq(s.len, 5)
  assert_eq(s.op_str, "rax, qword ptr [rbp+rcx*4]")
  let t = ok(b([0x4a, 0x8b, 0x04, 0xe0]), 0L)
  assert_eq(t.len, 4)
  assert_eq(t.op_str, "rax, qword ptr [rax+r12*8]")
}

test "decode: rip-relative disp32" {
  let ins = ok(b([0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00]), 0x2000L)
  assert_eq(ins.len, 7)
  assert_eq(ins.op_str, "rax, qword ptr [rip+0x10]")
  let z = ok(b([0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00]), 0x2000L)
  assert_eq(z.op_str, "rax, qword ptr [rip]")
}

test "decode: disp32 and negative disp8 rendering" {
  let d = ok(b([0x48, 0x8b, 0x80, 0x00, 0x01, 0x00, 0x00]), 0L)
  assert_eq(d.len, 7)
  assert_eq(d.op_str, "rax, qword ptr [rax+0x100]")
}

test "decode: shift group names (shl/shr/sar/sal) and counts" {
  let a = ok(b([0x48, 0xc1, 0xe0, 0x04]), 0L)
  assert_eq(a.mnemonic, "shl")
  assert_eq(a.len, 4)
  assert_eq(a.op_str, "rax, 0x4")
  let b1 = ok(b([0x48, 0xd1, 0xe0]), 0L)
  assert_eq(b1.mnemonic, "shl")
  assert_eq(b1.op_str, "rax, 1")
  let c1 = ok(b([0x48, 0xd3, 0xe0]), 0L)
  assert_eq(c1.mnemonic, "shl")
  assert_eq(c1.op_str, "rax, cl")
  let s = ok(b([0x48, 0xd1, 0xf0]), 0L)
  assert_eq(s.mnemonic, "sal")
  let r = ok(b([0x48, 0xc1, 0xf8, 0x3f]), 0L)
  assert_eq(r.mnemonic, "sar")
  assert_eq(r.len, 4)
}

test "decode: lock prefix folds into mnemonic (capstone convention)" {
  let ins = ok(b([0xf0, 0x48, 0xff, 0x00]), 0L)
  assert_eq(ins.mnemonic, "lock inc")
  assert_eq(ins.len, 4)
  assert_eq(ins.op_str, "qword ptr [rax]")
}

test "decode: setcc / cmovcc" {
  let s = ok(b([0x0f, 0x94, 0xc0]), 0L)
  assert_eq(s.mnemonic, "sete")
  assert_eq(s.len, 3)
  assert_eq(s.op_str, "al")
  let c = ok(b([0x0f, 0x44, 0xc0]), 0L)
  assert_eq(c.mnemonic, "cmove")
  assert_eq(c.len, 3)
  assert_eq(c.op_str, "eax, eax")
  let m = ok(b([0x48, 0x0f, 0x45, 0xc1]), 0L)
  assert_eq(m.mnemonic, "cmovne")
  assert_eq(m.len, 4)
  assert_eq(m.op_str, "rax, rcx")
}

test "decode: SSE movaps / movdqa / pxor / endbr64" {
  let a = ok(b([0x0f, 0x28, 0xc1]), 0L)
  assert_eq(a.mnemonic, "movaps")
  assert_eq(a.len, 3)
  assert_eq(a.op_str, "xmm0, xmm1")
  let d = ok(b([0x66, 0x0f, 0x6f, 0xc1]), 0L)
  assert_eq(d.mnemonic, "movdqa")
  assert_eq(d.len, 4)
  let p = ok(b([0x66, 0x0f, 0xef, 0xc1]), 0L)
  assert_eq(p.mnemonic, "pxor")
  assert_eq(p.len, 4)
  let e = ok(b([0xf3, 0x0f, 0x1e, 0xfa]), 0L)
  assert_eq(e.mnemonic, "endbr64")
  assert_eq(e.len, 4)
  assert_eq(e.op_str, "")
}

test "decode: movzx / movsx / movsxd source sizes" {
  let z = ok(b([0x0f, 0xb6, 0x00]), 0L)
  assert_eq(z.mnemonic, "movzx")
  assert_eq(z.len, 3)
  assert_eq(z.op_str, "eax, byte ptr [rax]")
  let s = ok(b([0x48, 0x0f, 0xbe, 0x00]), 0L)
  assert_eq(s.mnemonic, "movsx")
  assert_eq(s.len, 4)
  assert_eq(s.op_str, "rax, byte ptr [rax]")
  let d = ok(b([0x48, 0x63, 0xc0]), 0L)
  assert_eq(d.mnemonic, "movsxd")
  assert_eq(d.len, 3)
  assert_eq(d.op_str, "rax, eax")
}

test "decode: 67 address-size prefix uses 32-bit base regs" {
  let ins = ok(b([0x67, 0x8b, 0x45, 0xf8]), 0L)
  assert_eq(ins.mnemonic, "mov")
  assert_eq(ins.len, 4)
  assert_eq(ins.op_str, "eax, dword ptr [ebp-0x8]")
}

test "decode: segment override in memory operand" {
  let ins = ok(b([0x64, 0x48, 0x8b, 0x00]), 0L)
  assert_eq(ins.mnemonic, "mov")
  assert_eq(ins.len, 4)
  assert_eq(ins.op_str, "rax, qword ptr fs:[rax]")
}

test "decode: 8-bit regs with and without REX" {
  let no_rex = ok(b([0x88, 0x20]), 0L)
  assert_eq(no_rex.len, 2)
  assert_eq(no_rex.op_str, "byte ptr [rax], ah")
  let rex = ok(b([0x40, 0x88, 0x20]), 0L)
  assert_eq(rex.len, 3)
  assert_eq(rex.op_str, "byte ptr [rax], spl")
}

test "decode: group1 sign-extended imm8 (or rcx, -1)" {
  let ins = ok(b([0x48, 0x83, 0xc9, 0xff]), 0L)
  assert_eq(ins.mnemonic, "or")
  assert_eq(ins.len, 4)
  assert_eq(ins.op_str, "rcx, 0xffffffffffffffff")
}

test "decode: call/jmp indirect, push/pop mem, ret imm16" {
  let c = ok(b([0xff, 0xd0]), 0L)
  assert_eq(c.mnemonic, "call")
  assert_eq(c.len, 2)
  assert_eq(c.op_str, "rax")
  let j = ok(b([0xff, 0x25, 0x00, 0x00, 0x00, 0x00]), 0L)
  assert_eq(j.mnemonic, "jmp")
  assert_eq(j.len, 6)
  assert_eq(j.op_str, "qword ptr [rip]")
  let p = ok(b([0x8f, 0x00]), 0L)
  assert_eq(p.mnemonic, "pop")
  assert_eq(p.len, 2)
  let r = ok(b([0xc2, 0x08, 0x00]), 0L)
  assert_eq(r.mnemonic, "ret")
  assert_eq(r.len, 3)
  assert_eq(r.op_str, "0x8")
}

test "decode: lea has no size ptr and refuses register form" {
  let ins = ok(b([0x48, 0x8d, 0x4c, 0x24, 0x08]), 0L)
  assert_eq(ins.mnemonic, "lea")
  assert_eq(ins.len, 5)
  assert_eq(ins.op_str, "rcx, [rsp+0x8]")
  expect_invalid(b([0x48, 0x8d, 0xc0]))
}

test "decode: empty and truncated inputs refuse with Truncated" {
  expect_truncated(Bytes::from_array([]))
  expect_truncated(b([0x48, 0x8b]))
  expect_truncated(b([0xb8, 0x01, 0x00]))
  expect_truncated(b([0x0f]))
}

test "decode: unknown / unsupported opcodes refuse with Invalid" {
  let cases : Array[Array[Int]] = [
    [0x0f, 0x0b],       // ud2: valid but outside subset
    [0x06],             // push es: invalid in 64-bit mode
    [0xd6],             // salc: invalid in 64-bit mode
    [0x0f, 0x0d],       // prefetch: outside subset
    [0xc7, 0xc8, 0x01], // C7 /1: invalid reg field
    [0xff, 0xd8],       // FF /3: far call, refused
    [0x8f, 0xc8],       // 8F /1: invalid reg field
    [0x0f, 0x1f, 0xc8], // 0F 1F /1: reserved, only /0 is nop
    [0x0f, 0x6f, 0xc1], // MMX movq without 66: refused
    [0xf3, 0x0f, 0x1e, 0xfb], // not endbr64
  ]
  for c in cases {
    expect_invalid(b(c))
  }
}

test "disassemble: count limit, address continuity, stop on refusal" {
  let data = b([0x90, 0x90, 0x0f, 0x0b, 0x90])
  let two = disassemble(data, 0x1000L, 2)
  assert_eq(two.length(), 2)
  assert_eq(two[0].addr, 0x1000L)
  assert_eq(two[1].addr, 0x1001L)
  let stopped = disassemble(data, 0x1000L, 10)
  assert_eq(stopped.length(), 2)
  assert_eq(disassemble(data, 0L, 0).length(), 0)
  assert_eq(disassemble(Bytes::from_array([]), 0L, 5).length(), 0)
  let exact = disassemble(b([0xc3]), 0x2000L, 99)
  assert_eq(exact.length(), 1)
  assert_eq(exact[0].addr, 0x2000L)
}

test "disassemble: bytes field matches the source slice" {
  let data = b([0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20])
  let insns = disassemble(data, 0L, 2)
  assert_eq(insns.length(), 2)
  assert_eq(insns[1].bytes[0].to_int(), 0x48)
  assert_eq(insns[1].bytes[3].to_int(), 0x20)
  assert_eq(insns[1].addr, 3L)
}