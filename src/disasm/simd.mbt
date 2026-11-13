/// Shared SIMD tables and helpers used by both the legacy SSE (0F) path and
/// the VEX (C4/C5) path.

// SSE2 integer family (66-required): 2-op SSE, 3-op VEX (prefix v).
// Generated from capstone 5.0.7; empty = not in this family.
let sse2_int_name : Array[String] = [
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "punpcklbw", "punpcklwd", "punpckldq", "packsswb", "pcmpgtb", "pcmpgtw", "pcmpgtd", "packuswb",
  "punpckhbw", "punpckhwd", "punpckhdq", "packssdw", "punpcklqdq", "punpckhqdq", "", "",
  "", "", "", "", "pcmpeqb", "pcmpeqw", "pcmpeqd", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "",
  "", "psrlw", "psrld", "psrlq", "paddq", "pmullw", "", "",
  "", "", "", "", "paddusb", "paddusw", "pmaxub", "",
  "pavgb", "psraw", "psrad", "pavgw", "pmulhuw", "pmulhw", "", "",
  "psubsb", "psubsw", "pminsw", "", "paddsb", "paddsw", "pmaxsw", "",
  "", "psllw", "pslld", "psllq", "pmuludq", "", "psadbw", "",
  "psubb", "psubw", "psubd", "psubq", "paddb", "paddw", "paddd", "",
]

/// SSE/VEX compare predicates: capstone splits cmpps/vcmpps into a distinct
/// mnemonic per imm8 predicate (low 5 bits) and drops the immediate from the
/// operand text.
let cmp_pred : Array[String] = [
  "eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord",
  "eq_uq", "nge", "ngt", "false", "neq_oq", "ge", "gt", "true",
  "eq_os", "lt_oq", "le_oq", "unord_s", "neq_us", "nlt_uq", "nle_uq", "ord_s",
  "eq_us", "nge_uq", "ngt_uq", "false_os", "neq_os", "ge_oq", "gt_oq", "true_us",
]

/// SSE2 integer op (66 0F xx): two operands xmm, xmm/m128. Refuses without 66
/// (the MMX encoding) or with an F2/F3 prefix.
fn Dec::sse2_int(self : Dec, op : Int) -> Result[(String, String), @core.ParseError] {
  if self.has66 == false || self.rep != 0 {
    return Err(invalid("SSE2 integer without 66"))
  }
  let rm = self.read_rm(128, 16)
  Ok((sse2_int_name[op], gpr_name(128, rm.reg, self.has_rex) + ", " + rm.text))
}