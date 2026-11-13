/// A decoded x86-64 instruction.
///
/// `len` is the exact encoded length in bytes; `bytes` is the raw encoding
/// sliced from the input. `mnemonic` follows capstone conventions (e.g.
/// `movabs` for REX.W B8+rd, `sal` for shift /6, `lock ` folded into the
/// mnemonic when an F0 prefix is present).
pub(all) struct Insn {
  addr : Int64
  len : Int
  mnemonic : String
  op_str : String
  bytes : Bytes
} derive(Debug)

/// Decode a single instruction at the start of `data`, reported at `addr`.
///
/// Refuses with `Truncated` when the buffer ends mid-instruction and with
/// `Invalid` for opcodes outside the supported subset. Never panics, never
/// guesses: an unsupported encoding is an error, not a fabricated insn.
pub fn decode(data : Bytes, addr : Int64) -> Result[Insn, @core.ParseError] {
  let r = @core.Reader::new(data)
  match decode_inner(r, addr) {
    Ok((mn, ops)) => {
      let len = r.position()
      let bytes = Bytes::makei(len, fn(i) { data[i] })
      Ok({ addr, len, mnemonic: mn, op_str: ops, bytes })
    }
    Err(e) => Err(e)
  }
}

/// Decode up to `count` consecutive instructions starting at `addr`.
///
/// Stops early (returning what decoded cleanly) at the first refusal or at
/// end of buffer. The result is never longer than `count`.
pub fn disassemble(data : Bytes, addr : Int64, count : Int) -> Array[Insn] {
  let out : Array[Insn] = []
  if count <= 0 {
    return out
  }
  let r = @core.Reader::new(data)
  let mut a = addr
  for i = 0; i < count; i = i + 1 {
    let start = r.position()
    match decode_inner(r, a) {
      Ok((mn, ops)) => {
        let len = r.position() - start
        let bytes = Bytes::makei(len, fn(j) { data[start + j] })
        out.push({ addr: a, len, mnemonic: mn, op_str: ops, bytes })
        a = a + len.to_int64()
      }
      Err(e) => {
        match e {
          Truncated(_) => break
          _ => {
            // Outside the supported subset: report the raw byte faithfully and
            // keep going, rather than silently truncating the dump.
            let b = data[start]
            let _ = r.seek(start + 1)
            out.push({
              addr: a, len: 1, mnemonic: ".byte",
              op_str: hex_u64(b.to_int().to_int64()),
              bytes: Bytes::makei(1, fn(_) { b }),
            })
            a = a + 1
          }
        }
      }
    }
  }
  out
}

let hex_digits : Array[String] = [
  "0", "1", "2", "3", "4", "5", "6", "7",
  "8", "9", "a", "b", "c", "d", "e", "f",
]

/// Lowercase hex of the unsigned 64-bit pattern of `v`, prefixed `0x`.
fn hex_u64(v : Int64) -> String {
  let nibs : Array[Int] = []
  let mut x = v
  for i = 0; i < 16; i = i + 1 {
    nibs.push((x & 0xF).to_int())
    x = (x >> 4) & 0x0FFFFFFFFFFFFFFF
  }
  let mut out = ""
  let mut started = false
  for i = 15; i >= 0; i = i - 1 {
    let n = nibs[i]
    if n != 0 {
      started = true
    }
    if started {
      out = out + hex_digits[n]
    }
  }
  if started == false {
    out = "0"
  }
  "0x" + out
}

/// Sign-extend a zero-extended 32-bit value to 64 bits.
fn sext32(v : Int64) -> Int64 {
  if v >= 0x80000000L {
    v - 0x100000000L
  } else {
    v
  }
}

/// Sign-extend an unsigned byte to a signed 64-bit value.
fn sext8(v : Int) -> Int64 {
  (if v >= 128 {
    v - 256
  } else {
    v
  }).to_int64()
}

fn ptr_text(size : Int) -> String {
  match size {
    1 => "byte ptr "
    2 => "word ptr "
    4 => "dword ptr "
    8 => "qword ptr "
    10 => "tbyte ptr "
    16 => "xmmword ptr "
    32 => "ymmword ptr "
    _ => ""
  }
}

let gpr64_names : Array[String] = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]

let gpr32_names : Array[String] = [
  "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
  "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
]

let gpr16_names : Array[String] = [
  "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
  "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
]

let gpr8_names : Array[String] = [
  "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
  "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
]

let gpr8rex_names : Array[String] = [
  "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
  "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
]

let xmm_names : Array[String] = [
  "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
  "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
]

let ymm_names : Array[String] = [
  "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
  "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
]

/// Register name for a 0..15 index at the given operand size (128 = xmm,
/// 256 = ymm).
fn gpr_name(size : Int, idx : Int, has_rex : Bool) -> String {
  match size {
    64 => gpr64_names[idx]
    32 => gpr32_names[idx]
    16 => gpr16_names[idx]
    8 => if has_rex {
      gpr8rex_names[idx]
    } else {
      gpr8_names[idx]
    }
    128 => xmm_names[idx]
    256 => ymm_names[idx]
    _ => "?"
  }
}

let cc_names : Array[String] = [
  "o", "no", "b", "ae", "e", "ne", "be", "a",
  "s", "ns", "p", "np", "l", "ge", "le", "g",
]

let arith_names : Array[String] = [
  "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp",
]

let shift_names : Array[String] = [
  "rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar",
]

let le : @core.Endian = @core.Endian::Little

fn invalid(what : String) -> @core.ParseError {
  @core.ParseError::Invalid(what)
}