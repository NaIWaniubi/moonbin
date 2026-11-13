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
  /// Base relocations (data directory 5) as (rva, type) pairs, in block
  /// order. Type 0 (IMAGE_REL_BASED_ABSOLUTE) padding entries are skipped.
  relocations : Array[(Int64, Int)]
  /// Delay-load imports (data directory 13), flattened across descriptors.
  delay_imports : Array[@core.Import]
  /// TLS callback VAs (data directory 9, AddressOfCallBacks array).
  tls_callbacks : Array[Int64]
  /// Top-level resource type ids (data directory 2): numeric ids plus
  /// named types resolved to their negative name-RVA encoding.
  resource_types : Array[Int]
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
  let dir_sizes : Array[Int64] = []
  for i = 0; i < ndir.to_int(); i = i + 1 {
    let drva = need(r.u32(le), "data directory RVA")
    let dsize = need(r.u32(le), "data directory size")
    dirs.push(drva)
    dir_sizes.push(dsize)
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
  // Optional directories are best-effort: a malformed or unmapped optional
  // table must not refuse the whole image (core headers/imports/exports stay
  // strict above).
  let relocations = parse_relocations(r, le, infos, dirs, dir_sizes, size_of_headers) catch {
    _ => []
  }
  let delay_imports = parse_delay_imports(
    r, le, infos, dirs, dir_sizes, is64, image_base, size_of_headers,
  ) catch { _ => [] }
  let tls_callbacks = parse_tls(
    r, le, infos, dirs, dir_sizes, is64, image_base, size_of_headers,
  ) catch { _ => [] }
  let resource_types = parse_resource_types(r, le, infos, dirs, size_of_headers) catch {
    _ => []
  }
  {
    machine,
    is64,
    entry,
    image_base,
    sections,
    imports,
    exports,
    symbols,
    relocations,
    delay_imports,
    tls_callbacks,
    resource_types,
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

/// Base relocation blocks (data directory 5). Each block covers one page
/// (VirtualAddress) and carries u16 entries: high 4 bits type, low 12 bits
/// page offset. Type 0 (ABSOLUTE) is padding and is skipped. Blocks must fit
/// inside the directory size; anything else is refused, never guessed.
fn parse_relocations(
  r : @core.Reader,
  le : @core.Endian,
  infos : Array[SecInfo],
  dirs : Array[Int64],
  dir_sizes : Array[Int64],
  size_of_headers : Int64,
) -> Array[(Int64, Int)] raise PeFail {
  let out : Array[(Int64, Int)] = []
  if dirs.length() < 6 {
    return out
  }
  let rva = dirs[5]
  if rva == 0 {
    return out
  }
  let dir_size = dir_sizes[5]
  if dir_size < 8 {
    raise invalid("relocation directory smaller than one block header")
  }
  let base_off = rva_to_offset(infos, rva, size_of_headers)
  let file_len = r.length().to_int64()
  let mut consumed : Int64 = 0
  while consumed < dir_size {
    if dir_size - consumed < 8 {
      raise invalid("relocation block header runs past directory size")
    }
    let block_off = base_off.to_int64() + consumed
    if block_off + 8 > file_len {
      raise trunc("relocation block header")
    }
    let page_rva = u32_at(r, le, block_off.to_int(), "relocation page RVA")
    let block_size = u32_at(
      r, le, (block_off + 4).to_int(), "relocation block size",
    )
    if block_size < 8 || (block_size & 1) != 0 {
      raise invalid("relocation block size invalid")
    }
    if block_size > dir_size - consumed {
      raise invalid("relocation block runs past directory size")
    }
    if block_off + block_size > file_len {
      raise trunc("relocation block entries")
    }
    let nentries = ((block_size - 8) / 2).to_int()
    for i = 0; i < nentries; i = i + 1 {
      let entry = u16_at(
        r, le, (block_off + 8 + 2 * i.to_int64()).to_int(), "relocation entry",
      )
      let typ = (entry >> 12).to_int()
      if typ != 0 {
        out.push((page_rva + (entry & 0xFFF), typ))
      }
    }
    consumed = consumed + block_size
  }
  out
}

/// Delay-load import descriptors (data directory 13, ImgDelayDescr).
/// With attrs bit 0 (dlattrRva) set the pointer fields are RVAs (the modern
/// convention); otherwise they are VAs and are converted through image_base.
/// Thunk lists are walked like regular imports, preferring the INT.
fn parse_delay_imports(
  r : @core.Reader,
  le : @core.Endian,
  infos : Array[SecInfo],
  dirs : Array[Int64],
  dir_sizes : Array[Int64],
  is64 : Bool,
  image_base : Int64,
  size_of_headers : Int64,
) -> Array[@core.Import] raise PeFail {
  let out : Array[@core.Import] = []
  if dirs.length() < 14 {
    return out
  }
  let rva = dirs[13]
  if rva == 0 {
    return out
  }
  let dir_size = dir_sizes[13]
  if dir_size < 32 {
    raise invalid("delay import directory smaller than one descriptor")
  }
  let mut off = rva_to_offset(infos, rva, size_of_headers)
  let file_len = r.length().to_int64()
  let thunk_size = if is64 { 8 } else { 4 }
  let ordinal_flag : Int64 = if is64 { 0x8000000000000000 } else { 0x80000000 }
  let mut consumed : Int64 = 0
  while consumed + 32 <= dir_size {
    if off.to_int64() + 32 > file_len {
      raise trunc("delay import descriptor")
    }
    let attrs = u32_at(r, le, off, "delay import attrs")
    let name_ptr = u32_at(r, le, off + 4, "delay import DLL name")
    let _hmod = u32_at(r, le, off + 8, "delay import HMODULE")
    let int_ptr = u32_at(r, le, off + 12, "delay import INT")
    let iat_ptr = u32_at(r, le, off + 16, "delay import IAT")
    let _bound = u32_at(r, le, off + 20, "delay import bound IAT")
    let _unload = u32_at(r, le, off + 24, "delay import unload IAT")
    let _ts = u32_at(r, le, off + 28, "delay import timestamp")
    if attrs == 0 && name_ptr == 0 && int_ptr == 0 && iat_ptr == 0 {
      break // all-zero terminator descriptor
    }
    let rva_based = (attrs & 1) != 0
    let ptr_rva = fn(p : Int64) -> Int64 {
      if rva_based { p } else { p - image_base }
    }
    if name_ptr == 0 {
      raise invalid("delay import descriptor without DLL name")
    }
    let library = cstring_at(
      r,
      rva_to_offset(infos, ptr_rva(name_ptr), size_of_headers),
      "delay import DLL name",
    )
    let thunk_ptr = if int_ptr != 0 { int_ptr } else { iat_ptr }
    if thunk_ptr == 0 {
      raise invalid("delay import descriptor without thunks")
    }
    let mut toff = rva_to_offset(infos, ptr_rva(thunk_ptr), size_of_headers)
    while true {
      guard r.seek(toff) else { raise trunc("delay import thunk") }
      let thunk = if is64 {
        need(r.u64(le), "delay import thunk")
      } else {
        need(r.u32(le), "delay import thunk")
      }
      if thunk == 0 {
        break
      }
      if (thunk & ordinal_flag) != 0 {
        let ord = thunk & 0xFFFF
        out.push({ library, name: "#\{ord}" })
      } else {
        let hn_off = rva_to_offset(
          infos, ptr_rva(thunk & (ordinal_flag - 1)), size_of_headers,
        )
        guard r.seek(hn_off) else { raise trunc("delay import hint/name") }
        let _hint = need(r.u16(le), "delay import hint")
        let name = match r.cstring() {
          Some(s) => s
          None => raise trunc("delay import symbol name")
        }
        out.push({ library, name })
      }
      toff = toff + thunk_size
    }
    off = off + 32
    consumed = consumed + 32
  }
  out
}

/// TLS directory (data directory 9): the null-terminated AddressOfCallBacks
/// array, reported as absolute VAs. The directory must be large enough to
/// hold the AddressOfCallBacks field for the image class.
fn parse_tls(
  r : @core.Reader,
  le : @core.Endian,
  infos : Array[SecInfo],
  dirs : Array[Int64],
  dir_sizes : Array[Int64],
  is64 : Bool,
  image_base : Int64,
  size_of_headers : Int64,
) -> Array[Int64] raise PeFail {
  let out : Array[Int64] = []
  if dirs.length() < 10 {
    return out
  }
  let rva = dirs[9]
  if rva == 0 {
    return out
  }
  let dir_size = dir_sizes[9]
  let min_dir : Int64 = if is64 { 40 } else { 24 }
  if dir_size < min_dir {
    raise invalid("TLS directory smaller than AddressOfCallBacks field")
  }
  let base_off = rva_to_offset(infos, rva, size_of_headers)
  // AddressOfCallBacks sits at offset 24 (PE32+) / 12 (PE32) and is a VA.
  let cb_field = base_off + (if is64 { 24 } else { 12 })
  let cb_va = if is64 {
    u64_at(r, le, cb_field, "TLS AddressOfCallBacks")
  } else {
    u32_at(r, le, cb_field, "TLS AddressOfCallBacks")
  }
  if cb_va == 0 {
    return out
  }
  let cb_rva = cb_va - image_base
  if cb_rva <= 0 {
    raise invalid("TLS callback array VA below image base")
  }
  let mut off = rva_to_offset(infos, cb_rva, size_of_headers)
  let file_len = r.length().to_int64()
  let ptr_size = if is64 { 8 } else { 4 }
  while true {
    if off.to_int64() + ptr_size.to_int64() > file_len {
      raise trunc("TLS callback array")
    }
    let cb = if is64 {
      u64_at(r, le, off, "TLS callback")
    } else {
      u32_at(r, le, off, "TLS callback")
    }
    if cb == 0 {
      break
    }
    out.push(cb)
    off = off + ptr_size
  }
  out
}

/// Resource directory (data directory 2): top-level type ids only. Numeric
/// ids are reported as-is; named types are reported as the negative of their
/// name RVA (the IMAGE_RESOURCE_NAME_IS_STRING encoding), since resolving the
/// UTF-16 name is out of scope for v0.1. Child subtrees are bounds-checked
/// but not flattened.
fn parse_resource_types(
  r : @core.Reader,
  le : @core.Endian,
  infos : Array[SecInfo],
  dirs : Array[Int64],
  size_of_headers : Int64,
) -> Array[Int] raise PeFail {
  let out : Array[Int] = []
  if dirs.length() < 3 {
    return out
  }
  let rva = dirs[2]
  if rva == 0 {
    return out
  }
  let root_off = rva_to_offset(infos, rva, size_of_headers)
  let file_len = r.length().to_int64()
  if root_off.to_int64() + 16 > file_len {
    raise trunc("resource root directory")
  }
  let _chars = u32_at(r, le, root_off, "resource characteristics")
  let _ts = u32_at(r, le, root_off + 4, "resource timestamp")
  let _maj = u16_at(r, le, root_off + 8, "resource major version")
  let _min = u16_at(r, le, root_off + 10, "resource minor version")
  let nnamed = u16_at(r, le, root_off + 12, "resource named entry count")
  let nid = u16_at(r, le, root_off + 14, "resource id entry count")
  let count = nnamed + nid
  // Every entry is 8 bytes and must fit in the file.
  if count > (file_len - root_off.to_int64() - 16) / 8 {
    raise invalid("resource entry count exceeds file size")
  }
  for i = 0; i < count.to_int(); i = i + 1 {
    let eoff = root_off + 16 + 8 * i
    let name_field = u32_at(r, le, eoff, "resource entry name")
    let offset_field = u32_at(r, le, eoff + 4, "resource entry offset")
    let id = if (name_field & 0x80000000) != 0 {
      // Named type: keep the name-RVA encoding, negated. The RVA must map
      // to real file bytes (the UTF-16 name itself is not decoded here).
      let name_rva = name_field & 0x7FFFFFFF
      if name_rva == 0 {
        raise invalid("resource name RVA is zero")
      }
      let _ = rva_to_offset(infos, name_rva, size_of_headers)
      -(name_rva.to_int())
    } else {
      name_field.to_int()
    }
    if (offset_field & 0x80000000) != 0 {
      // Subdirectory: validate the child header lies inside the file.
      let child = (offset_field & 0x7FFFFFFF).to_int()
      if child < 16 || root_off.to_int64() + child.to_int64() + 16 > file_len {
        raise invalid("resource subdirectory offset out of range")
      }
    }
    out.push(id)
  }
  out
}

fn u64_at(
  r : @core.Reader,
  le : @core.Endian,
  off : Int,
  what : String,
) -> Int64 raise PeFail {
  guard r.seek(off) else { raise trunc(what) }
  need(r.u64(le), what)
}