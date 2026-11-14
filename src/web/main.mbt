// moonbin wasm playground entry.
//
// The browser glue (web/index.html) instantiates this module with a virtual
// filesystem containing one file, "input.bin", and argv
// ["moonbin-web", "report", "input.bin"]. main reads that file, runs the full
// analysis pipeline (detect -> parse -> disasm -> strings/entropy) and prints
// exactly one JSON object on stdout, which the glue renders into the DOM.
//
// Refusals are data, not crashes: a parse failure still reports the raw
// strings/entropy of the buffer alongside the error message.

/// Lowercase hex of a non-negative Int64, prefixed 0x (same style as the CLI).
fn hex(v : Int64) -> String {
  if v < 0 {
    return v.to_string()
  }
  if v == 0 {
    return "0x0"
  }
  let mut x = v
  let mut out = ""
  while x > 0 {
    let d = (x % 16).to_int()
    let code = if d < 10 { 48 + d } else { 87 + d }
    out = String::from_array([code.unsafe_to_char()]) + out
    x = x / 16
  }
  "0x" + out
}

/// Lowercase hex of raw bytes, no prefix, two digits per byte.
fn bytes_hex(b : Bytes) -> String {
  let mut out = ""
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    let hi = v / 16
    let lo = v % 16
    let hc = if hi < 10 { 48 + hi } else { 87 + hi }
    let lc = if lo < 10 { 48 + lo } else { 87 + lo }
    out = out + String::from_array([hc.unsafe_to_char(), lc.unsafe_to_char()])
  }
  out
}

/// Minimal JSON string escaping (same rules as the CLI's jesc).
fn jesc(s : String) -> String {
  let mut out = ""
  for ch in s {
    let c = ch.to_int()
    if c == 34 {
      out = out + "\\\""
    } else if c == 92 {
      out = out + "\\\\"
    } else if c < 32 {
      out = out + " "
    } else {
      out = out + String::from_array([ch])
    }
  }
  out
}

fn perr(e : @core.ParseError) -> String {
  match e {
    Truncated(s) => "truncated: " + s
    BadMagic(s) => "bad magic: " + s
    Invalid(s) => "invalid: " + s
  }
}

/// Fixed 4-decimal rendering of a non-negative entropy value.
fn fmt4(v : Float) -> String {
  let scaled = (v * 10000.0).round().to_int()
  let n = if scaled < 0 { 0 } else { scaled }
  let ip = n / 10000
  let mut fp = (n % 10000).to_string()
  while fp.length() < 4 {
    fp = "0" + fp
  }
  "\{ip}.\{fp}"
}

let string_cap : Int = 200
let symbol_cap : Int = 200
let disasm_count : Int = 40

/// Shared tail fields: size, strings (capped), entropy. Always present, even
/// when the container parse was refused.
fn raw_part(data : Bytes) -> String {
  let hits = @inspect.strings(data, 4)
  let shown = if hits.length() > string_cap { string_cap } else { hits.length() }
  let items : Array[String] = []
  for i = 0; i < shown; i = i + 1 {
    let h = hits[i]
    items.push("{\"offset\":\"\{hex(h.offset)}\",\"text\":\"\{jesc(h.text)}\"}")
  }
  "\"size\":\{data.length()},\"strings\":[" + items.join(",") +
  "],\"strings_truncated\":\{hits.length() > string_cap},\"entropy\":\{fmt4(@inspect.entropy(data))}"
}

fn regions_json(regions : Array[@core.Region]) -> String {
  let items : Array[String] = []
  for r in regions {
    items.push("{\"name\":\"\{jesc(r.name)}\",\"offset\":\"\{hex(r.offset)}\",\"size\":\"\{hex(r.size)}\",\"vaddr\":\"\{hex(r.vaddr)}\",\"flags\":\"\{jesc(r.flags)}\"}")
  }
  "[" + items.join(",") + "]"
}

fn imports_json(imports : Array[@core.Import]) -> String {
  let items : Array[String] = []
  for i in imports {
    items.push("{\"library\":\"\{jesc(i.library)}\",\"name\":\"\{jesc(i.name)}\"}")
  }
  "[" + items.join(",") + "]"
}

fn exports_json(exports : Array[@core.Export]) -> String {
  let items : Array[String] = []
  for e in exports {
    items.push("{\"name\":\"\{jesc(e.name)}\",\"ordinal\":\{e.ordinal},\"rva\":\"\{hex(e.rva)}\"}")
  }
  "[" + items.join(",") + "]"
}

fn symbols_json(symbols : Array[@core.Symbol]) -> String {
  let items : Array[String] = []
  let shown = if symbols.length() > symbol_cap {
    symbol_cap
  } else {
    symbols.length()
  }
  for i = 0; i < shown; i = i + 1 {
    let s = symbols[i]
    items.push("{\"name\":\"\{jesc(s.name)}\",\"value\":\"\{hex(s.value)}\",\"size\":\"\{hex(s.size)}\",\"kind\":\"\{jesc(s.kind)}\",\"bind\":\"\{jesc(s.bind)}\"}")
  }
  "[" + items.join(",") + "]"
}

fn section_entropy_json(data : Bytes, regions : Array[@core.Region]) -> String {
  let items : Array[String] = []
  for se in @inspect.section_entropy(data, regions) {
    items.push("{\"name\":\"\{jesc(se.name)}\",\"entropy\":\{fmt4(se.entropy)}}")
  }
  "[" + items.join(",") + "]"
}

/// Disassemble the .text region (x86 family only; the decoder is x86-64).
fn disasm_json(data : Bytes, regions : Array[@core.Region], machine_ok : Bool) -> String {
  if !machine_ok {
    return "{\"insns\":[],\"note\":\"machine not supported by the x86-64 decoder\"}"
  }
  let mut text : @core.Region? = None
  for r in regions {
    if r.name == ".text" {
      text = Some(r)
    }
  }
  match text {
    None => "{\"insns\":[],\"note\":\"no .text section found\"}"
    Some(r) => {
      let rd = @core.Reader::new(data)
      if !rd.seek(r.offset.to_int()) {
        return "{\"insns\":[],\"note\":\"text offset out of range\"}"
      }
      match rd.take(r.size.to_int()) {
        None => "{\"insns\":[],\"note\":\"text region truncated\"}"
        Some(code) => {
          let items : Array[String] = []
          for i in @disasm.disassemble(code, r.vaddr, disasm_count) {
            items.push("{\"addr\":\"\{hex(i.addr)}\",\"len\":\{i.len},\"bytes\":\"\{bytes_hex(i.bytes)}\",\"mnemonic\":\"\{jesc(i.mnemonic)}\",\"op_str\":\"\{jesc(i.op_str)}\"}")
          }
          "{\"insns\":[" + items.join(",") + "],\"note\":\"\"}"
        }
      }
    }
  }
}

fn dwarf_json(data : Bytes, regions : Array[@core.Region]) -> String {
  let ls : Array[String] = []
  match @dwarf.decode_lines(data, regions) {
    Ok(rows) => {
      for r in rows {
        ls.push("{\"addr\":\"\{hex(r.addr)}\",\"file\":\"\{jesc(r.file)}\",\"line\":\{r.line}}")
      }
    }
    Err(_) => ()
  }
  let fs : Array[String] = []
  match @dwarf.decode_funcs(data, regions) {
    Ok(rows) => {
      for f in rows {
        fs.push("{\"name\":\"\{jesc(f.name)}\",\"low\":\"\{hex(f.low)}\",\"high\":\"\{hex(f.high)}\"}")
      }
    }
    Err(_) => ()
  }
  "{\"lines\":[" + ls.join(",") + "],\"funcs\":[" + fs.join(",") + "]}"
}

fn pe_report(p : @pe.Pe, data : Bytes) -> String {
  let machine_ok = p.machine == 0x8664 || p.machine == 0x14C
  "{\"ok\":true,\"format\":\"PE\",\"machine\":\{p.machine},\"is64\":\{p.is64},\"entry\":\"\{hex(p.entry)}\",\"base\":\"\{hex(p.image_base)}\"," +
  "\"sections\":" + regions_json(p.sections) +
  ",\"imports\":" + imports_json(p.imports) +
  ",\"exports\":" + exports_json(p.exports) +
  ",\"symbols\":" + symbols_json(p.symbols) +
  ",\"disasm\":" + disasm_json(data, p.sections, machine_ok) +
  ",\"section_entropy\":" + section_entropy_json(data, p.sections) +
  ",\"dwarf\":" + dwarf_json(data, p.sections) + "," + raw_part(data) + "}"
}

fn elf_report(e : @elf.Elf, data : Bytes) -> String {
  let machine_ok = e.machine == 62 || e.machine == 3
  let endian = match e.endian {
    Little => "little"
    Big => "big"
  }
  "{\"ok\":true,\"format\":\"ELF\",\"class\":\{e.class},\"endian\":\"\{endian}\",\"machine\":\{e.machine},\"entry\":\"\{hex(e.entry)}\",\"base\":\"0x0\"," +
  "\"sections\":" + regions_json(e.sections) +
  ",\"segments\":" + regions_json(e.segments) +
  ",\"imports\":" + imports_json(e.imports) +
  ",\"exports\":" + exports_json(e.exports) +
  ",\"symbols\":" + symbols_json(e.symbols) +
  ",\"disasm\":" + disasm_json(data, e.sections, machine_ok) +
  ",\"section_entropy\":" + section_entropy_json(data, e.sections) +
  ",\"dwarf\":" + dwarf_json(data, e.sections) + "," + raw_part(data) + "}"
}

fn macho_report(m : @macho.MachO, data : Bytes) -> String {
  let machine_ok = m.cpu == 0x01000007 || m.cpu == 7
  "{\"ok\":true,\"format\":\"Mach-O\",\"class\":\{m.class},\"machine\":\{m.cpu},\"entry\":\"\{hex(m.entry)}\",\"base\":\"0x0\"," +
  "\"sections\":" + regions_json(m.sections) +
  ",\"imports\":" + imports_json(m.imports) +
  ",\"exports\":" + exports_json(m.exports) +
  ",\"symbols\":" + symbols_json(m.symbols) +
  ",\"disasm\":" + disasm_json(data, m.sections, machine_ok) +
  ",\"section_entropy\":" + section_entropy_json(data, m.sections) +
  ",\"dwarf\":" + dwarf_json(data, m.sections) + "," + raw_part(data) + "}"
}

fn refused(format : String, msg : String, data : Bytes) -> String {
  "{\"ok\":false,\"format\":\"\{format}\",\"error\":\"\{jesc(msg)}\",\"sections\":[],\"imports\":[],\"exports\":[],\"symbols\":[],\"disasm\":{\"insns\":[],\"note\":\"\"},\"section_entropy\":[],\"dwarf\":{\"lines\":[],\"funcs\":[]}," +
  raw_part(data) + "}"
}

fn report(data : Bytes) -> String {
  match @format.detect(data) {
    @format.Pe => {
      match @pe.parse(data) {
        Ok(p) => pe_report(p, data)
        Err(e) => refused("PE", perr(e), data)
      }
    }
    @format.Elf => {
      match @elf.parse(data) {
        Ok(e) => elf_report(e, data)
        Err(e) => refused("ELF", perr(e), data)
      }
    }
    @format.MachO => {
      match @macho.parse(data) {
        Ok(m) => macho_report(m, data)
        Err(e) => refused("Mach-O", perr(e), data)
      }
    }
    @format.Unknown => refused("unknown", "unrecognized container magic", data)
  }
}

fn main {
  let argv = @env.args()
  let path = if argv.length() >= 3 { argv[2] } else { "input.bin" }
  let data = @fs.read_file_to_bytes(path) catch {
    @fs.IOError(msg) => {
      println("{\"ok\":false,\"format\":\"unknown\",\"error\":\"\{jesc(msg)}\",\"sections\":[],\"imports\":[],\"exports\":[],\"symbols\":[],\"disasm\":{\"insns\":[],\"note\":\"\"},\"section_entropy\":[],\"size\":0,\"strings\":[],\"strings_truncated\":false,\"entropy\":0.0000}")
      return
    }
  }
  println(report(data))
}