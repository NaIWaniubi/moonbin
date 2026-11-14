/// DWARF v4/v5 source mapping: .debug_line line programs and .debug_info
/// subprograms. Best-effort on unknown forms/opcodes (skip), strict on
/// truncation. Never panics.

pub(all) struct LineEntry {
  addr : Int64
  file : String
  line : Int
} derive(Debug)

pub(all) struct FuncEntry {
  name : String
  low : Int64
  high : Int64
} derive(Debug)

priv suberror DwErr {
  T(String)
  I(String)
}

priv struct Rd {
  data : Bytes
  mut pos : Int
}

fn Rd::u8(self : Rd) -> Int raise DwErr {
  if self.pos >= self.data.length() { raise DwErr::T("u8") }
  let v = self.data[self.pos].to_int()
  self.pos = self.pos + 1
  v
}

fn Rd::u16(self : Rd) -> Int raise DwErr {
  let a = self.u8()
  let b = self.u8()
  a | (b << 8)
}

fn Rd::u32(self : Rd) -> Int64 raise DwErr {
  let mut v : Int64 = 0
  for i = 0; i < 4; i = i + 1 {
    v = v | (self.u8().to_int64() << (i * 8))
  }
  v
}

fn Rd::u64(self : Rd) -> Int64 raise DwErr {
  let mut v : Int64 = 0
  for i = 0; i < 8; i = i + 1 {
    v = v | (self.u8().to_int64() << (i * 8))
  }
  v
}

fn Rd::uleb(self : Rd) -> Int raise DwErr {
  let mut r = 0
  let mut s = 0
  while true {
    let b = self.u8()
    r = r | ((b & 0x7F) << s)
    if (b & 0x80) == 0 { break }
    s = s + 7
  }
  r
}

fn Rd::sleb(self : Rd) -> Int raise DwErr {
  let mut r = 0
  let mut s = 0
  let mut b = 0
  while true {
    b = self.u8()
    r = r | ((b & 0x7F) << s)
    s = s + 7
    if (b & 0x80) == 0 { break }
  }
  if (b & 0x40) != 0 { r = r - (1 << s) }
  r
}

fn Rd::cstr(self : Rd) -> String raise DwErr {
  let chars : Array[Char] = []
  while true {
    let b = self.u8()
    if b == 0 { break }
    chars.push(b.unsafe_to_char())
  }
  String::from_array(chars)
}

fn Rd::skip(self : Rd, n : Int) -> Unit raise DwErr {
  for i = 0; i < n; i = i + 1 {
    let _ = self.u8()
  }
}

fn section(data : Bytes, regions : Array[@core.Region], name : String) -> Bytes raise DwErr {
  for r in regions {
    if r.name == name {
      let off = r.offset.to_int()
      let sz = r.size.to_int()
      if off < 0 || sz < 0 || off + sz > data.length() {
        raise DwErr::T("section out of bounds: " + name)
      }
      return Bytes::makei(sz, fn(i) { data[off + i] })
    }
  }
  raise DwErr::I("missing section: " + name)
}

fn opt_section(data : Bytes, regions : Array[@core.Region], name : String) -> Bytes {
  section(data, regions, name) catch { _ => Bytes::from_array([]) }
}

fn to_core(e : DwErr) -> @core.ParseError {
  match e {
    T(s) => @core.ParseError::Truncated(s)
    I(s) => @core.ParseError::Invalid(s)
  }
}

/// Decode all .debug_line units into (addr, file, line) rows.
pub fn decode_lines(data : Bytes, regions : Array[@core.Region]) -> Result[Array[LineEntry], @core.ParseError] {
  let rows = decode_lines_inner(data, regions) catch { e => return Err(to_core(e)) }
  Ok(rows)
}

fn decode_lines_inner(data : Bytes, regions : Array[@core.Region]) -> Array[LineEntry] raise DwErr {
  let line = section(data, regions, ".debug_line")
  let line_str = opt_section(data, regions, ".debug_line_str")
  let rd : Rd = { data: line, pos: 0 }
  let out : Array[LineEntry] = []
  while rd.pos < line.length() {
    let unit_len = rd.u32().to_int()
    // Raw section bytes are alignment-padded with zeros after the last unit.
    if unit_len == 0 {
      break
    }
    let unit_end = rd.pos + unit_len
    if unit_end > line.length() {
      raise DwErr::T("line unit past section")
    }
    let version = rd.u16()
    let mut addr_size = 8
    if version >= 5 {
      addr_size = rd.u8()
      let _ = rd.u8() // segment_selector_size
    }
    let header_len = rd.u32().to_int()
    let header_end = rd.pos + header_len
    let min_inst = rd.u8()
    let max_ops = rd.u8()
    let _default_stmt = rd.u8()
    let line_base = { let b = rd.u8(); if b >= 128 { b - 256 } else { b } }
    let line_range = rd.u8()
    let opcode_base = rd.u8()
    let std_lens : Array[Int] = []
    for i = 0; i < opcode_base - 1; i = i + 1 {
      std_lens.push(rd.u8())
    }
    let files : Array[String] = []
    if version <= 4 {
      // directories
      while true {
        let d = rd.cstr()
        if d == "" { break }
      }
      // files (1-based)
      while true {
        let n = rd.cstr()
        if n == "" { break }
        let _ = rd.uleb()
        let _ = rd.uleb()
        let _ = rd.uleb()
        files.push(n)
      }
    } else {
      // v5 directory table
      let _ = read_v5_table(rd, line_str, false)
      // v5 file table (0-based)
      let names = read_v5_table(rd, line_str, true)
      for n in names { files.push(n) }
    }
    // program
    let mut address : Int64 = 0
    let mut op_index = 0
    let mut file = if version <= 4 { 1 } else { 0 }
    let mut ln = 1
    let prog_end = if unit_end < line.length() { unit_end } else { line.length() }
    rd.pos = header_end
    while rd.pos < prog_end {
      let op = rd.u8()
      if op == 0 {
        let elen = rd.uleb()
        let sub = rd.u8()
        let payload = elen - 1
        if sub == 1 {
          address = 0
          op_index = 0
          file = if version <= 4 { 1 } else { 0 }
          ln = 1
        } else if sub == 2 {
          address = if addr_size == 8 { rd.u64() } else { rd.u32() }
          op_index = 0
        } else if sub == 3 {
          let n = rd.cstr()
          let _ = rd.uleb()
          let _ = rd.uleb()
          let _ = rd.uleb()
          files.push(n)
        } else {
          rd.skip(payload - (if sub == 2 { addr_size } else { 0 }))
        }
      } else if op == 1 {
        out.push({ addr: address, file: file_name(files, file, version), line: ln })
      } else if op == 2 {
        let n = rd.uleb()
        address = address + (min_inst * ((op_index + n) / max_ops)).to_int64()
        op_index = (op_index + n) % max_ops
      } else if op == 3 {
        ln = ln + rd.sleb()
      } else if op == 4 {
        file = rd.uleb()
      } else if op == 5 {
        let _ = rd.uleb()
      } else if op == 8 {
        let adj = (255 - opcode_base) / line_range
        address = address + (min_inst * ((op_index + adj) / max_ops)).to_int64()
        op_index = (op_index + adj) % max_ops
      } else if op == 9 {
        address = address + rd.u16().to_int64()
        op_index = 0
      } else if op == 12 {
        let _ = rd.uleb()
      } else if op >= opcode_base {
        let adj = op - opcode_base
        let aadv = adj / line_range
        let ladv = line_base + (adj % line_range)
        address = address + (min_inst * ((op_index + aadv) / max_ops)).to_int64()
        op_index = (op_index + aadv) % max_ops
        ln = ln + ladv
        out.push({ addr: address, file: file_name(files, file, version), line: ln })
      } else {
        // standard op with operands per std_lens
        let n = std_lens[op - 1]
        for i = 0; i < n; i = i + 1 {
          let _ = rd.uleb()
        }
      }
    }
    rd.pos = unit_end
  }
  out
}

fn file_name(files : Array[String], idx : Int, version : Int) -> String {
  let i = if version <= 4 { idx - 1 } else { idx }
  if i >= 0 && i < files.length() { files[i] } else { "" }
}

/// Read a v5 directory/file table; return the path names (for file table).
fn read_v5_table(rd : Rd, line_str : Bytes, want_names : Bool) -> Array[String] raise DwErr {
  let nformats = rd.u8()
  let forms : Array[(Int, Int)] = []
  for i = 0; i < nformats; i = i + 1 {
    let ct = rd.uleb()
    let fm = rd.uleb()
    forms.push((ct, fm))
  }
  let count = rd.uleb()
  let names : Array[String] = []
  for e = 0; e < count; e = e + 1 {
    let mut name = ""
    for i = 0; i < forms.length(); i = i + 1 {
      let (ct, fm) = forms[i]
      let s = read_form_str(rd, fm, line_str)
      if ct == 1 && want_names { name = s }
      if ct != 1 { let _ = s }
    }
    names.push(name)
  }
  names
}

/// Read a form, returning its string value (for path forms) or skipping it.
fn read_form_str(rd : Rd, form : Int, line_str : Bytes) -> String raise DwErr {
  match form {
    0x08 => rd.cstr()
    0x1F => {
      let off = rd.u32().to_int()
      cstr_at(line_str, off)
    }
    0x0E => {
      let off = rd.u32().to_int()
      cstr_at(line_str, off)
    }
    0x0F => { let _ = rd.uleb(); "" }
    0x0B => { let _ = rd.u8(); "" }
    0x05 => { let _ = rd.u16(); "" }
    0x06 => { let _ = rd.u32(); "" }
    0x07 => { let _ = rd.u64(); "" }
    0x1E => { rd.skip(16); "" }
    0x0D => { let _ = rd.sleb(); "" }
    _ => { let _ = rd.uleb(); "" }
  }
}

fn cstr_at(b : Bytes, off : Int) -> String raise DwErr {
  if off < 0 || off >= b.length() { raise DwErr::T("str offset") }
  let chars : Array[Char] = []
  let mut i = off
  while i < b.length() {
    let c = b[i].to_int()
    i = i + 1
    if c == 0 { break }
    chars.push(c.unsafe_to_char())
  }
  String::from_array(chars)
}