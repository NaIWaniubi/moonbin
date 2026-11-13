// Regression: relative branch targets must be correct when disassemble() uses
// one shared cursor over many instructions (kernel32.dll `jno rel8` at 0x1008).
test "negative rel8 target with shared cursor" {
  // nop; jno -8  -> target = 0x1003 - 8 = 0x9fb
  let code = Bytes::from_array([0x90, 0x71, 0xF8].map(fn(x) { x.to_byte() }))
  let insns = disassemble(code, 0x1000, 2)
  assert_eq(insns.length(), 2)
  assert_eq(insns[1].mnemonic, "jno")
  assert_eq(insns[1].op_str, "0xffb")
}

test "positive rel8 target with shared cursor" {
  // nop; jmp +4 -> target = 0x1003 + 4 = 0x1007
  let code = Bytes::from_array([0x90, 0xEB, 0x04].map(fn(x) { x.to_byte() }))
  let insns = disassemble(code, 0x1000, 2)
  assert_eq(insns[1].mnemonic, "jmp")
  assert_true(insns[1].op_str.contains("0x1007"))
}