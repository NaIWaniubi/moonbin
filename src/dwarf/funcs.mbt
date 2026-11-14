/// .debug_info subprogram extraction (name + low_pc + high_pc).

priv struct Abbrev {
  tag : Int
  attrs : Array[(Int, Int, Int)]
}

fn load_abbrevs(ab : Bytes, off : Int) -> Map[Int, Abbrev] raise DwErr {
  let rd : Rd = { data: ab, pos: off }
  let m : Map[Int, Abbrev] = Map([])
  while true {
    let code = rd.uleb()
    if code == 0 { break }
    let tag = rd.uleb()
    let _ = rd.u8() // has_children
    let attrs : Array[(Int, Int, Int)] = []
    while true {
      let at = rd.uleb()
      let fm = rd.uleb()
      if at == 0 && fm == 0 { break }
      let mut imp = 0
      if fm == 0x21 { imp = rd.sleb() }
      attrs.push((at, fm, imp))
    }
    m[code] = { tag, attrs }
  }
  m
}

fn read_attr(rd : Rd, form : Int, addr_size : Int, strsec : Bytes, linesec : Bytes) -> (Int64, String) raise DwErr {
  match form {
    0x01 => (if addr_size == 8 { rd.u64() } else { rd.u32() }, "")
    0x08 => (0L, rd.cstr())
    0x0E => (0L, cstr_at(strsec, rd.u32().to_int()))
    0x1F => (0L, cstr_at(linesec, rd.u32().to_int()))
    0x06 => (rd.u32(), "")
    0x07 => (rd.u64(), "")
    0x0B => (rd.u8().to_int64(), "")
    0x05 => (rd.u16().to_int64(), "")
    0x0F => (rd.uleb().to_int64(), "")
    0x0D => (rd.sleb().to_int64(), "")
    0x19 => (0L, "")
    0x21 => (0L, "")
    0x1E => { rd.skip(16); (0L, "") }
    0x03 => { let n = rd.u16(); rd.skip(n); (0L, "") }
    0x17 => (rd.u32(), "")
    0x13 => (rd.u32(), "")
    0x0C => (rd.u8().to_int64(), "")
    0x18 => { let n = rd.uleb(); rd.skip(n); (0L, "") }
    0x0A => { let n = rd.u8(); rd.skip(n); (0L, "") }
    0x04 => { let n = rd.u32().to_int(); rd.skip(n); (0L, "") }
    _ => (rd.uleb().to_int64(), "")
  }
}

/// Decode .debug_info subprograms into (name, low, high).
pub fn decode_funcs(data : Bytes, regions : Array[@core.Region]) -> Result[Array[FuncEntry], @core.ParseError] {
  let rows = decode_funcs_inner(data, regions) catch { e => return Err(to_core(e)) }
  Ok(rows)
}

fn decode_funcs_inner(data : Bytes, regions : Array[@core.Region]) -> Array[FuncEntry] raise DwErr {
  let info = section(data, regions, ".debug_info")
  let abbrev = section(data, regions, ".debug_abbrev")
  let strsec = opt_section(data, regions, ".debug_str")
  let linesec = opt_section(data, regions, ".debug_line_str")
  let rd : Rd = { data: info, pos: 0 }
  let out : Array[FuncEntry] = []
  while rd.pos < info.length() {
    let unit_len = rd.u32().to_int()
    if unit_len == 0 {
      break
    }
    let unit_end = rd.pos + unit_len
    if unit_end > info.length() {
      raise DwErr::T("info unit past section")
    }
    let version = rd.u16()
    let mut addr_size = 8
    let mut abbrev_off = 0
    if version >= 5 {
      let _ = rd.u8() // unit_type
      addr_size = rd.u8()
      abbrev_off = rd.u32().to_int()
    } else {
      abbrev_off = rd.u32().to_int()
      addr_size = rd.u8()
    }
    let abbrevs = load_abbrevs(abbrev, abbrev_off)
    while rd.pos < unit_end {
      let code = rd.uleb()
      if code == 0 { continue }
      let ab = match abbrevs.get(code) {
        Some(a) => a
        None => raise DwErr::I("unknown abbrev code")
      }
      let mut name = ""
      let mut low : Int64 = 0
      let mut has_low = false
      let mut high : Int64 = 0
      let mut high_is_addr = false
      let mut has_high = false
      let mut decl = false
      for i = 0; i < ab.attrs.length(); i = i + 1 {
        let (at, fm, _imp) = ab.attrs[i]
        let (num, s) = read_attr(rd, fm, addr_size, strsec, linesec)
        if at == 0x03 {
          name = s
        } else if at == 0x11 {
          low = num
          has_low = true
        } else if at == 0x12 {
          high = num
          high_is_addr = fm == 0x01
          has_high = true
        } else if at == 0x3C {
          decl = true
        }
      }
      if ab.tag == 0x2E && name != "" && has_low && has_high && !decl {
        let hi = if high_is_addr { high } else { low + high }
        out.push({ name, low, high: hi })
      }
    }
    rd.pos = unit_end
  }
  out
}