/// PE32 / PE32+ image parser.
///
/// Walks DOS header -> NT signature -> COFF header -> optional header ->
/// section table -> data directories, then resolves import and export
/// tables through RVA->file-offset mapping. Malformed or truncated input is
/// refused with `Truncated` / `BadMagic` / `Invalid`; nothing here panics and
/// nothing is guessed.

/// A parsed PE image.
pub(all) struct Pe {
  /// COFF machine type (e.g. 0x8664 = AMD64, 0x14C = i386).
  machine : Int
  /// true for PE32+ (optional header magic 0x20b).
  is64 : Bool
  /// AddressOfEntryPoint as an RVA; absolute VA = image_base + entry.
  entry : Int64
  /// ImageBase from the optional header.
  image_base : Int64
  sections : Array[@core.Region]
  imports : Array[@core.Import]
  exports : Array[@core.Export]
  symbols : Array[@core.Symbol]
} derive(Debug)

type PErr = @core.ParseError

/// Internal refusal carrier; converted to `Result` at the public boundary.
priv suberror PeFail {
  Fail(PErr)
} derive(Debug)

/// Section facts needed for RVA->file-offset mapping.
priv struct SecInfo {
  va : Int64
  raw_ptr : Int64
  raw_size : Int64
}

fn trunc(what : String) -> PeFail {
  PeFail::Fail(PErr::Truncated(what))
}

fn invalid(what : String) -> PeFail {
  PeFail::Fail(PErr::Invalid(what))
}

fn bad_magic(what : String) -> PeFail {
  PeFail::Fail(PErr::BadMagic(what))
}

/// Lift a bounds-checked read into a `Truncated` refusal.
fn need(opt : Int64?, what : String) -> Int64 raise PeFail {
  match opt {
    Some(v) => v
    None => raise trunc(what)
  }
}

fn need_u8(opt : Int?, what : String) -> Int raise PeFail {
  match opt {
    Some(v) => v
    None => raise trunc(what)
  }
}

///|
pub fn parse(data : Bytes) -> Result[Pe, @core.ParseError] {
  try Ok(parse_inner(data)) catch {
    Fail(e) => Err(e)
  }
}

fn parse_inner(data : Bytes) -> Pe raise PeFail {
  let r = @core.Reader::new(data)
  let le = @core.Endian::Little
  let file_len = r.length().to_int64()
  // DOS header: "MZ" and the e_lfanew pointer at 0x3C.
  if need(r.u16(le), "DOS magic") != 0x5A4D {
    raise bad_magic("DOS MZ magic")
  }
  guard r.seek(0x3C) else { raise trunc("DOS e_lfanew field") }
  let e_lfanew = need(r.u32(le), "DOS e_lfanew")
  if e_lfanew < 0x40 || e_lfanew > file_len {
    raise invalid("e_lfanew out of range")
  }
  // NT headers: "PE\0\0" signature then the COFF header.
  guard r.seek(e_lfanew.to_int()) else { raise trunc("NT headers") }
  if need(r.u32(le), "PE signature") != 0x00004550 {
    raise bad_magic("PE signature")
  }
  let machine = need(r.u16(le), "COFF machine").to_int()
  let num_sections = need(r.u16(le), "COFF section count").to_int()
  let _timestamp = need(r.u32(le), "COFF timestamp")
  let symtab_ptr = need(r.u32(le), "COFF symbol table pointer")
  let num_symbols = need(r.u32(le), "COFF symbol count")
  let opt_size = need(r.u16(le), "COFF optional header size").to_int()
  let _characteristics = need(r.u16(le), "COFF characteristics")
  let opt_start = e_lfanew.to_int() + 24
  if opt_size < 2 {
    raise invalid("optional header missing")
  }
  if opt_start.to_int64() + opt_size.to_int64() > file_len {
    raise trunc("optional header")
  }
  guard r.seek(opt_start) else { raise trunc("optional header") }
  let magic = need(r.u16(le), "optional header magic")
  let is64 = match magic {
    0x10B => false
    0x20B => true
    _ => raise bad_magic("optional header magic (not PE32/PE32+)")
  }
  // An image must carry the full Windows-specific fields; the directory
  // count field sits at 92 (PE32) / 108 (PE32+).
  let min_opt = if is64 { 112 } else { 96 }
  if opt_size < min_opt {
    raise invalid("optional header smaller than PE image minimum")
  }
  // AddressOfEntryPoint is at offset 16 in both formats.
  guard r.seek(opt_start + 16) else { raise trunc("AddressOfEntryPoint") }
  let entry = need(r.u32(le), "AddressOfEntryPoint")
  let image_base = if is64 {
    guard r.seek(opt_start + 24) else { raise trunc("ImageBase") }
    need(r.u64(le), "ImageBase")
  } else {
    guard r.seek(opt_start + 28) else { raise trunc("ImageBase") }
    need(r.u32(le), "ImageBase")
  }
  // SizeOfHeaders is at offset 60 in both formats.
  guard r.seek(opt_start + 60) else { raise trunc("SizeOfHeaders") }
  let size_of_headers = need(r.u32(le), "SizeOfHeaders")
  // Data directories: export = 0, import = 1.
  let dir_base = if is64 { 112 } else { 96 }
  guard r.seek(opt_start + dir_base - 4) else {
    raise trunc("NumberOfRvaAndSizes")
  }
  let ndir = need(r.u32(le), "NumberOfRvaAndSizes")
  let avail = ((opt_size - dir_base) / 8).to_int64()
  if ndir > 16 || ndir > avail {
    raise invalid("data directory count out of range")
  }
  let dirs : Array[Int64] = []
  for i = 0; i < ndir.to_int(); i = i + 1 {
    let drva = need(r.u32(le), "data directory RVA")
    let _dsize = need(r.u32(le), "data directory size")
    dirs.push(drva)
  }
  // Section table.
  let sec_start = opt_start + opt_size
  if sec_start.to_int64() + (num_sections * 40).to_int64() > file_len {
    raise trunc("section table")
  }
  guard r.seek(sec_start) else { raise trunc("section table") }
  let strtab_start = symtab_ptr + num_symbols * 18
  let sections : Array[@core.Region] = []
  let infos : Array[SecInfo] = []
  for i = 0; i < num_sections; i = i + 1 {
    let name_raw = match r.take(8) {
      Some(b) => b
      None => raise trunc("section name")
    }
    let _vsize = need(r.u32(le), "section VirtualSize")
    let va = need(r.u32(le), "section VirtualAddress")
    let raw_size = need(r.u32(le), "section SizeOfRawData")
    let raw_ptr = need(r.u32(le), "section PointerToRawData")
    let _reloc_ptr = need(r.u32(le), "section relocation pointer")
    let _lineno_ptr = need(r.u32(le), "section line number pointer")
    let _nreloc = need(r.u16(le), "section relocation count")
    let _nlineno = need(r.u16(le), "section line number count")
    let chars = need(r.u32(le), "section characteristics")
    if raw_size > 0 && raw_ptr + raw_size > file_len {
      raise trunc("section raw data")
    }
    // "/N" names point into the COFF string table that follows the symbol
    // table; long_name restores the cursor after resolving.
    let name = long_name(name_raw, r, strtab_start, symtab_ptr != 0, "section name")
    infos.push({ va, raw_ptr, raw_size })
    sections.push({
      name,
      offset: raw_ptr,
      size: raw_size,
      vaddr: va,
      flags: section_flags(chars),
    })
  }
  let imports = parse_imports(r, le, infos, dirs, is64, size_of_headers)
  let exports = parse_exports(r, le, infos, dirs, size_of_headers)
  let symbols = parse_symbols(r, le, symtab_ptr, num_symbols, strtab_start)
  {
    machine,
    is64,
    entry,
    image_base,
    sections,
    imports,
    exports,
    symbols,
  }
}

/// Map an RVA to a file offset through the section table; RVAs inside the
/// headers map to themselves. Only raw (on-disk) bytes are mappable.
fn rva_to_offset(
  infos : Array[SecInfo],
  rva : Int64,
  size_of_headers : Int64,
) -> Int raise PeFail {
  if rva <= 0 {
    raise invalid("zero RVA")
  }
  for i = 0; i < infos.length(); i = i + 1 {
    let s = infos[i]
    if s.raw_size > 0 && rva >= s.va && rva - s.va < s.raw_size {
      return (s.raw_ptr + (rva - s.va)).to_int()
    }
  }
  if rva < size_of_headers {
    return rva.to_int()
  }
  raise invalid("RVA not mapped by any section")
}

/// Decode an 8-byte name field: plain ASCII, or "/N" referencing the COFF
/// string table. Refuses unresolvable long names instead of guessing.
fn long_name(
  raw : Bytes,
  r : @core.Reader,
  strtab_start : Int64,
  has_strtab : Bool,
  what : String,
) -> String raise PeFail {
  if raw.length() == 0 {
    return ""
  }
  if raw[0].to_int() != 47 {
    return ascii_name(raw)
  }
  if !has_strtab {
    raise invalid("\{what}: long name without a string table")
  }
  let mut off : Int64 = 0
  let mut digits = 0
  for i = 1; i < raw.length(); i = i + 1 {
    let c = raw[i].to_int()
    if c == 0 {
      break
    }
    if c < 48 || c > 57 {
      raise invalid("\{what}: non-decimal long name offset")
    }
    off = off * 10 + (c - 48).to_int64()
    digits = digits + 1
  }
  if digits == 0 {
    raise invalid("\{what}: empty long name offset")
  }
  let pos = strtab_start + off
  if pos < strtab_start + 4 || pos >= r.length().to_int64() {
    raise invalid("\{what}: long name offset out of range")
  }
  let saved = r.position()
  guard r.seek(pos.to_int()) else { raise trunc(what) }
  let s = match r.cstring() {
    Some(s) => s
    None => {
      let _ = r.seek(saved)
      raise trunc(what)
    }
  }
  let _ = r.seek(saved)
  s
}

/// ASCII bytes up to the first NUL (an 8-byte name may have no NUL).
fn ascii_name(b : Bytes) -> String {
  let chars : Array[Char] = []
  for i = 0; i < b.length(); i = i + 1 {
    if b[i] == 0 {
      break
    }
    chars.push(b[i].to_char())
  }
  String::from_array(chars)
}

/// Human-readable permission flags from IMAGE_SCN_* characteristics.
fn section_flags(chars : Int64) -> String {
  let cs : Array[Char] = []
  if (chars & 0x40000000) != 0 {
    cs.push('r')
  }
  if (chars & 0x80000000) != 0 {
    cs.push('w')
  }
  if (chars & 0x20000000) != 0 {
    cs.push('x')
  }
  if cs.length() == 0 {
    cs.push('-')
  }
  String::from_array(cs)
}

fn cstring_at(r : @core.Reader, off : Int, what : String) -> String raise PeFail {
  guard r.seek(off) else { raise trunc(what) }
  match r.cstring() {
    Some(s) => s
    None => raise trunc(what)
  }
}

fn u32_at(
  r : @core.Reader,
  le : @core.Endian,
  off : Int,
  what : String,
) -> Int64 raise PeFail {
  guard r.seek(off) else { raise trunc(what) }
  need(r.u32(le), what)
}

fn u16_at(
  r : @core.Reader,
  le : @core.Endian,
  off : Int,
  what : String,
) -> Int64 raise PeFail {
  guard r.seek(off) else { raise trunc(what) }
  need(r.u16(le), what)
}

/// Import descriptors (data directory 1): DLL name plus the thunk list.
/// Prefers OriginalFirstThunk; falls back to FirstThunk. Ordinal imports
/// become "#<ordinal>" names.
fn parse_imports(
  r : @core.Reader,
  le : @core.Endian,
  infos : Array[SecInfo],
  dirs : Array[Int64],
  is64 : Bool,
  size_of_headers : Int64,
) -> Array[@core.Import] raise PeFail {
  let out : Array[@core.Import] = []
  if dirs.length() < 2 {
    return out
  }
  let rva = dirs[1]
  if rva == 0 {
    return out
  }
  let mut off = rva_to_offset(infos, rva, size_of_headers)
  let thunk_size = if is64 { 8 } else { 4 }
  let ordinal_flag : Int64 = if is64 { 0x8000000000000000 } else { 0x80000000 }
  while true {
    guard r.seek(off) else { raise trunc("import descriptor") }
    let oft = need(r.u32(le), "import OriginalFirstThunk")
    let _ts = need(r.u32(le), "import timestamp")
    let _fc = need(r.u32(le), "import forwarder chain")
    let name_rva = need(r.u32(le), "import DLL name RVA")
    let ft = need(r.u32(le), "import FirstThunk")
    if oft == 0 && name_rva == 0 && ft == 0 {
      break // all-zero terminator descriptor
    }
    let library = cstring_at(
      r,
      rva_to_offset(infos, name_rva, size_of_headers),
      "import DLL name",
    )
    let thunk_rva = if oft != 0 { oft } else { ft }
    if thunk_rva == 0 {
      raise invalid("import descriptor without thunks")
    }
    let mut toff = rva_to_offset(infos, thunk_rva, size_of_headers)
    while true {
      guard r.seek(toff) else { raise trunc("import thunk") }
      let thunk = if is64 {
        need(r.u64(le), "import thunk")
      } else {
        need(r.u32(le), "import thunk")
      }
      if thunk == 0 {
        break
      }
      if (thunk & ordinal_flag) != 0 {
        let ord = thunk & 0xFFFF
        out.push({ library, name: "#\{ord}" })
      } else {
        let hn_off = rva_to_offset(
          infos, thunk & (ordinal_flag - 1), size_of_headers,
        )
        guard r.seek(hn_off) else { raise trunc("import hint/name") }
        let _hint = need(r.u16(le), "import hint")
        let name = match r.cstring() {
          Some(s) => s
          None => raise trunc("import symbol name")
        }
        out.push({ library, name })
      }
      toff = toff + thunk_size
    }
    off = off + 20
  }
  out
}

/// Export directory (data directory 0): named exports with their ordinals
/// and function RVAs. Ordinal-only (unnamed) exports are not emitted.
fn parse_exports(
  r : @core.Reader,
  le : @core.Endian,
  infos : Array[SecInfo],
  dirs : Array[Int64],
  size_of_headers : Int64,
) -> Array[@core.Export] raise PeFail {
  let out : Array[@core.Export] = []
  if dirs.length() < 1 {
    return out
  }
  let rva = dirs[0]
  if rva == 0 {
    return out
  }
  let base_off = rva_to_offset(infos, rva, size_of_headers)
  guard r.seek(base_off) else { raise trunc("export directory") }
  let _chars = need(r.u32(le), "export characteristics")
  let _ts = need(r.u32(le), "export timestamp")
  let _maj = need(r.u16(le), "export major version")
  let _min = need(r.u16(le), "export minor version")
  let _name = need(r.u32(le), "export DLL name RVA")
  let ord_base = need(r.u32(le), "export ordinal base")
  let nfuncs = need(r.u32(le), "export NumberOfFunctions")
  let nnames = need(r.u32(le), "export NumberOfNames")
  let funcs_rva = need(r.u32(le), "export AddressOfFunctions")
  let names_rva = need(r.u32(le), "export AddressOfNames")
  let ords_rva = need(r.u32(le), "export AddressOfNameOrdinals")
  if nnames > nfuncs {
    raise invalid("export name count exceeds function count")
  }
  let file_len = r.length().to_int64()
  if nnames > file_len / 4 || nfuncs > file_len / 4 {
    raise invalid("export table count exceeds file size")
  }
  for i = 0; i < nnames.to_int(); i = i + 1 {
    let i64 = i.to_int64()
    let name_rva = u32_at(
      r, le,
      rva_to_offset(infos, names_rva + 4 * i64, size_of_headers),
      "export name RVA",
    )
    let oi = u16_at(
      r, le,
      rva_to_offset(infos, ords_rva + 2 * i64, size_of_headers),
      "export ordinal index",
    )
    if oi >= nfuncs {
      raise invalid("export ordinal index out of range")
    }
    let frva = u32_at(
      r, le,
      rva_to_offset(infos, funcs_rva + 4 * oi, size_of_headers),
      "export function RVA",
    )
    let name = cstring_at(
      r,
      rva_to_offset(infos, name_rva, size_of_headers),
      "export name",
    )
    out.push({ name, ordinal: (ord_base + oi).to_int(), rva: frva })
  }
  out
}

/// COFF symbol table (usually stripped from images). Skips auxiliary
/// entries; resolves "/N" long names through the string table.
fn parse_symbols(
  r : @core.Reader,
  le : @core.Endian,
  symtab_ptr : Int64,
  num_symbols : Int64,
  strtab_start : Int64,
) -> Array[@core.Symbol] raise PeFail {
  let out : Array[@core.Symbol] = []
  if symtab_ptr == 0 || num_symbols == 0 {
    return out
  }
  let file_len = r.length().to_int64()
  if symtab_ptr + num_symbols * 18 > file_len {
    raise trunc("COFF symbol table")
  }
  // The string table follows the symbol table; its first u32 is its size.
  let strtab_size = if strtab_start + 4 <= file_len {
    u32_at(r, le, strtab_start.to_int(), "COFF string table size")
  } else {
    0
  }
  if strtab_size != 0 &&
    (strtab_size < 4 || strtab_start + strtab_size > file_len) {
    raise trunc("COFF string table")
  }
  let count = num_symbols.to_int()
  let mut i = 0
  let mut pos = symtab_ptr.to_int()
  while i < count {
    guard r.seek(pos) else { raise trunc("COFF symbol") }
    let name_raw = match r.take(8) {
      Some(b) => b
      None => raise trunc("COFF symbol name")
    }
    let value = need(r.u32(le), "symbol value")
    let sec = need(r.u16(le), "symbol section number")
    let typ = need(r.u16(le), "symbol type")
    let sclass = need_u8(r.u8(), "symbol storage class")
    let naux = need_u8(r.u8(), "symbol aux count")
    let name = long_name(
      name_raw, r, strtab_start, strtab_size != 0, "symbol name",
    )
    let kind = if (typ & 0x20) != 0 {
      "func"
    } else if typ == 0 {
      "notype"
    } else {
      "object"
    }
    let bind = match sclass {
      2 => "global" // IMAGE_SYM_CLASS_EXTERNAL
      3 => "local" // IMAGE_SYM_CLASS_STATIC
      105 => "weak" // IMAGE_SYM_CLASS_WEAK_EXTERNAL
      _ => "other"
    }
    let shndx = if sec == 0 || sec >= 0xFFFE { -1 } else { sec.to_int() }
    out.push({ name, value, size: 0, kind, bind, shndx })
    i = i + 1 + naux
    pos = pos + 18 * (1 + naux)
  }
  out
}