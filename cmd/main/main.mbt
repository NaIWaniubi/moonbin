// moonbin CLI: info / sections / symbols / imports / exports / disasm.
// Reads a real binary, detects the container, and prints a report.
// Exit codes: 0 ok, 1 parse refused, 2 usage / IO error.

struct View {
  format : String
  machine : Int
  entry : Int64
  base : Int64
  sections : Array[@core.Region]
  symbols : Array[@core.Symbol]
  imports : Array[@core.Import]
  exports : Array[@core.Export]
}

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

fn load_view(data : Bytes) -> Result[View, String] {
  match @format.detect(data) {
    @format.Pe => {
      match @pe.parse(data) {
        Ok(p) => Ok({
          format: "PE", machine: p.machine, entry: p.entry, base: p.image_base,
          sections: p.sections, symbols: p.symbols, imports: p.imports, exports: p.exports,
        })
        Err(e) => Err("PE parse refused: " + perr(e))
      }
    }
    @format.Elf => {
      match @elf.parse(data) {
        Ok(e) => Ok({
          format: "ELF", machine: e.machine, entry: e.entry, base: 0,
          sections: e.sections, symbols: e.symbols, imports: e.imports, exports: e.exports,
        })
        Err(e) => Err("ELF parse refused: " + perr(e))
      }
    }
    @format.MachO => {
      match @macho.parse(data) {
        Ok(m) => Ok({
          format: "Mach-O", machine: m.cpu, entry: m.entry, base: 0,
          sections: m.sections, symbols: m.symbols, imports: m.imports, exports: m.exports,
        })
        Err(e) => Err("Mach-O parse refused: " + perr(e))
      }
    }
    @format.Unknown => Err("unrecognized container magic")
  }
}

fn text_region(v : View) -> @core.Region? {
  for r in v.sections {
    if r.name == ".text" {
      return Some(r)
    }
  }
  None
}

fn print_info(v : View, json : Bool) -> Unit {
  if json {
    println("{\"format\":\"\{v.format}\",\"machine\":\{v.machine},\"entry\":\"\{hex(v.entry)}\",\"base\":\"\{hex(v.base)}\",\"sections\":\{v.sections.length()},\"symbols\":\{v.symbols.length()},\"imports\":\{v.imports.length()},\"exports\":\{v.exports.length()}}")
  } else {
    println("format   \{v.format}")
    println("machine  \{v.machine}")
    println("entry    \{hex(v.entry)}")
    println("base     \{hex(v.base)}")
    println("sections \{v.sections.length()}  symbols \{v.symbols.length()}  imports \{v.imports.length()}  exports \{v.exports.length()}")
  }
}

fn print_regions(v : View, json : Bool) -> Unit {
  if json {
    let items : Array[String] = []
    for r in v.sections {
      items.push("{\"name\":\"\{jesc(r.name)}\",\"offset\":\"\{hex(r.offset)}\",\"size\":\"\{hex(r.size)}\",\"vaddr\":\"\{hex(r.vaddr)}\",\"flags\":\"\{jesc(r.flags)}\"}")
    }
    println("[" + items.join(",") + "]")
  } else {
    for r in v.sections {
      println("\{r.name}\t\{hex(r.offset)}\t\{hex(r.size)}\t\{hex(r.vaddr)}\t\{r.flags}")
    }
  }
}

fn print_symbols(v : View, json : Bool) -> Unit {
  if json {
    let items : Array[String] = []
    for s in v.symbols {
      items.push("{\"name\":\"\{jesc(s.name)}\",\"value\":\"\{hex(s.value)}\",\"kind\":\"\{jesc(s.kind)}\",\"bind\":\"\{jesc(s.bind)}\"}")
    }
    println("[" + items.join(",") + "]")
  } else {
    for s in v.symbols {
      println("\{hex(s.value)}\t\{s.kind}\t\{s.bind}\t\{s.name}")
    }
  }
}

fn print_imports(v : View, json : Bool) -> Unit {
  if json {
    let items : Array[String] = []
    for i in v.imports {
      items.push("{\"library\":\"\{jesc(i.library)}\",\"name\":\"\{jesc(i.name)}\"}")
    }
    println("[" + items.join(",") + "]")
  } else {
    for i in v.imports {
      println("\{i.library}\t\{i.name}")
    }
  }
}

fn print_exports(v : View, json : Bool) -> Unit {
  if json {
    let items : Array[String] = []
    for e in v.exports {
      items.push("{\"name\":\"\{jesc(e.name)}\",\"ordinal\":\{e.ordinal},\"rva\":\"\{hex(e.rva)}\"}")
    }
    println("[" + items.join(",") + "]")
  } else {
    for e in v.exports {
      println("\{e.ordinal}\t\{hex(e.rva)}\t\{e.name}")
    }
  }
}

fn print_disasm(data : Bytes, v : View, count : Int, json : Bool) -> Unit {
  match text_region(v) {
    None => {
      println("no .text section found")
    }
    Some(r) => {
      let rd = @core.Reader::new(data)
      if !rd.seek(r.offset.to_int()) {
        println("text offset out of range")
        return
      }
      match rd.take(r.size.to_int()) {
        None => println("text region truncated")
        Some(code) => {
          let insns = @disasm.disassemble(code, r.vaddr, count)
          if json {
            let items : Array[String] = []
            for i in insns {
              items.push("{\"addr\":\"\{hex(i.addr)}\",\"mnemonic\":\"\{jesc(i.mnemonic)}\",\"op_str\":\"\{jesc(i.op_str)}\",\"len\":\{i.len}}")
            }
            println("[" + items.join(",") + "]")
          } else {
            for i in insns {
              println("\{hex(i.addr)}:\t\{i.mnemonic}\t\{i.op_str}")
            }
          }
        }
      }
    }
  }
}

fn print_strings(data : Bytes, json : Bool) -> Unit {
  let hits = @inspect.strings(data, 4)
  if json {
    let items : Array[String] = []
    for h in hits {
      items.push("{\"offset\":\"\{hex(h.offset)}\",\"text\":\"\{jesc(h.text)}\"}")
    }
    println("[" + items.join(",") + "]")
  } else {
    for h in hits {
      println("\{hex(h.offset)}\t\{h.text}")
    }
  }
}

fn print_entropy(data : Bytes, json : Bool) -> Unit {
  let e = @inspect.entropy(data)
  if json {
    println("{\"entropy\":\{e}}")
  } else {
    println("entropy \{e} / 8.0")
  }
}

fn parse_int(s : String) -> Int? {
  let mut n = 0
  let mut any = false
  for ch in s {
    let c = ch.to_int()
    if c < 48 || c > 57 {
      return None
    }
    n = n * 10 + (c - 48)
    any = true
  }
  if any { Some(n) } else { None }
}

fn usage() -> Unit {
  println("usage: moonbin <info|sections|symbols|imports|exports|disasm|strings|entropy> <file> [--json] [--count N]")
}

fn main {
  let argv = @env.args()
  if argv.length() < 3 {
    usage()
    @sys.exit(2)
  }
  let cmd = argv[1]
  let path = argv[2]
  let mut json = false
  let mut count = 40
  let mut i = 3
  while i < argv.length() {
    if argv[i] == "--json" {
      json = true
    } else if argv[i] == "--count" && i + 1 < argv.length() {
      count = match parse_int(argv[i + 1]) {
        Some(n) => n
        None => 40
      }
      i = i + 1
    }
    i = i + 1
  }
  let data = @fs.read_file_to_bytes(path) catch {
    @fs.IOError(msg) => {
      println("io error: \{msg}")
      abort("")
    }
  }
  // Raw-byte analyses do not require a parsed container.
  if cmd == "strings" {
    print_strings(data, json)
    return
  }
  if cmd == "entropy" {
    print_entropy(data, json)
    return
  }
  let v = match load_view(data) {
    Ok(view) => view
    Err(msg) => {
      println(msg)
      abort("")
    }
  }
  match cmd {
    "info" => print_info(v, json)
    "sections" => print_regions(v, json)
    "symbols" => print_symbols(v, json)
    "imports" => print_imports(v, json)
    "exports" => print_exports(v, json)
    "disasm" => print_disasm(data, v, count, json)
    _ => {
      usage()
      @sys.exit(2)
    }
  }
}