/// ELF32 / ELF64 parser, both endians. Pure and bounds-checked: malformed or
/// truncated input yields `Err`, never a panic and never a guess.

/// Parsed ELF image metadata (see INTERFACES.md, frozen v0.1).
pub(all) struct Elf {
  /// 32 or 64 (EI_CLASS).
  class : Int
  /// Byte order (EI_DATA).
  endian : @core.Endian
  /// e_machine (e.g. 62 = x86-64, 20 = PowerPC).
  machine : Int
  /// e_entry virtual address.
  entry : Int64
  /// Section header table, in table order.
  sections : Array[@core.Region]
  /// Program header table, in table order.
  segments : Array[@core.Region]
  /// SHT_SYMTAB and SHT_DYNSYM entries, in section-table order.
  symbols : Array[@core.Symbol]
  /// DT_NEEDED library names from SHT_DYNAMIC.
  imports : Array[@core.Import]
  /// Defined SHT_DYNSYM symbols.
  exports : Array[@core.Export]
} derive(Debug)

/// Internal carrier so helpers can `raise` and `parse` converts to `Result`.
priv suberror ElfErr {
  ElfErr(@core.ParseError)
}

// Section header types.
let sht_null : Int64 = 0
let sht_symtab : Int64 = 2
let sht_dynamic : Int64 = 6
let sht_nobits : Int64 = 8
let sht_dynsym : Int64 = 11

// Extended numbering escapes.
let shn_xindex : Int64 = 0xFFFF
let pn_xnum : Int64 = 0xFFFF

// Dynamic tags.
let dt_null : Int64 = 0
let dt_needed : Int64 = 1

/// Raw section header, class/endian normalized to Int64.
priv struct Shdr {
  name_off : Int64
  typ : Int64
  flags : Int64
  addr : Int64
  offset : Int64
  size : Int64
  link : Int64
  info : Int64
  entsize : Int64
}

/// Raw program header fields we surface.
priv struct Phdr {
  typ : Int64
  flags : Int64
  offset : Int64
  vaddr : Int64
  filesz : Int64
}

/// Raw symbol table entry.
priv struct Sym {
  name_off : Int64
  info : Int64
  shndx : Int64
  value : Int64
  size : Int64
}

///|
fn trunc(what : String) -> @core.ParseError {
  @core.ParseError::Truncated(what)
}

///|
fn bad(what : String) -> @core.ParseError {
  @core.ParseError::Invalid(what)
}

///|
fn[T] need(opt : T?, what : String) -> T raise ElfErr {
  match opt {
    Some(v) => v
    None => raise ElfErr(trunc(what))
  }
}

///|
fn read_addr(
  r : @core.Reader,
  endian : @core.Endian,
  class : Int
) -> Int64? {
  if class == 64 {
    r.u64(endian)
  } else {
    r.u32(endian)
  }
}

///|
fn read_shdr(
  r : @core.Reader,
  endian : @core.Endian,
  class : Int
) -> Shdr raise ElfErr {
  let name_off = need(r.u32(endian), "sh_name")
  let typ = need(r.u32(endian), "sh_type")
  if class == 64 {
    let flags = need(r.u64(endian), "sh_flags")
    let addr = need(r.u64(endian), "sh_addr")
    let offset = need(r.u64(endian), "sh_offset")
    let size = need(r.u64(endian), "sh_size")
    let link = need(r.u32(endian), "sh_link")
    let info = need(r.u32(endian), "sh_info")
    let _align = need(r.u64(endian), "sh_addralign")
    let entsize = need(r.u64(endian), "sh_entsize")
    { name_off, typ, flags, addr, offset, size, link, info, entsize }
  } else {
    let flags = need(r.u32(endian), "sh_flags")
    let addr = need(r.u32(endian), "sh_addr")
    let offset = need(r.u32(endian), "sh_offset")
    let size = need(r.u32(endian), "sh_size")
    let link = need(r.u32(endian), "sh_link")
    let info = need(r.u32(endian), "sh_info")
    let _align = need(r.u32(endian), "sh_addralign")
    let entsize = need(r.u32(endian), "sh_entsize")
    { name_off, typ, flags, addr, offset, size, link, info, entsize }
  }
}

///|
fn read_phdr(
  r : @core.Reader,
  endian : @core.Endian,
  class : Int
) -> Phdr raise ElfErr {
  let typ = need(r.u32(endian), "p_type")
  if class == 64 {
    let flags = need(r.u32(endian), "p_flags")
    let offset = need(r.u64(endian), "p_offset")
    let vaddr = need(r.u64(endian), "p_vaddr")
    let _paddr = need(r.u64(endian), "p_paddr")
    let filesz = need(r.u64(endian), "p_filesz")
    let _memsz = need(r.u64(endian), "p_memsz")
    let _align = need(r.u64(endian), "p_align")
    { typ, flags, offset, vaddr, filesz }
  } else {
    let offset = need(r.u32(endian), "p_offset")
    let vaddr = need(r.u32(endian), "p_vaddr")
    let _paddr = need(r.u32(endian), "p_paddr")
    let filesz = need(r.u32(endian), "p_filesz")
    let _memsz = need(r.u32(endian), "p_memsz")
    let flags = need(r.u32(endian), "p_flags")
    let _align = need(r.u32(endian), "p_align")
    { typ, flags, offset, vaddr, filesz }
  }
}

///|
fn read_sym(
  r : @core.Reader,
  endian : @core.Endian,
  class : Int
) -> Sym raise ElfErr {
  let name_off = need(r.u32(endian), "st_name")
  if class == 64 {
    let info = need(r.u8(), "st_info").to_int64()
    let _other = need(r.u8(), "st_other")
    let shndx = need(r.u16(endian), "st_shndx")
    let value = need(r.u64(endian), "st_value")
    let size = need(r.u64(endian), "st_size")
    { name_off, info, shndx, value, size }
  } else {
    let value = need(r.u32(endian), "st_value")
    let size = need(r.u32(endian), "st_size")
    let info = need(r.u8(), "st_info").to_int64()
    let _other = need(r.u8(), "st_other")
    let shndx = need(r.u16(endian), "st_shndx")
    { name_off, info, shndx, value, size }
  }
}

///|
fn segment_name(t : Int64) -> String {
  match t {
    0 => "NULL"
    1 => "LOAD"
    2 => "DYNAMIC"
    3 => "INTERP"
    4 => "NOTE"
    5 => "SHLIB"
    6 => "PHDR"
    7 => "TLS"
    0x6474E550 => "GNU_EH_FRAME"
    0x6474E551 => "GNU_STACK"
    0x6474E552 => "GNU_RELRO"
    0x6474E553 => "GNU_PROPERTY"
    _ => "UNKNOWN"
  }
}

///|
fn symbol_kind(t : Int64) -> String {
  match t {
    0 => "notype"
    1 => "object"
    2 => "func"
    3 => "section"
    4 => "file"
    5 => "common"
    6 => "tls"
    _ => "unknown"
  }
}

///|
fn symbol_bind(b : Int64) -> String {
  match b {
    0 => "local"
    1 => "global"
    2 => "weak"
    10 => "unique"
    _ => "unknown"
  }
}

/// Section flags -> "rwx": r = SHF_ALLOC, w = SHF_WRITE, x = SHF_EXECINSTR.
fn section_flags(f : Int64) -> String {
  let mut out = ""
  if (f & 2) != 0 {
    out = out + "r"
  }
  if (f & 1) != 0 {
    out = out + "w"
  }
  if (f & 4) != 0 {
    out = out + "x"
  }
  out
}

/// Segment flags -> "rwx": PF_R = 4, PF_W = 2, PF_X = 1.
fn segment_flags(f : Int64) -> String {
  let mut out = ""
  if (f & 4) != 0 {
    out = out + "r"
  }
  if (f & 2) != 0 {
    out = out + "w"
  }
  if (f & 1) != 0 {
    out = out + "x"
  }
  out
}

/// Read a NUL-terminated string from a string table section, refusing
/// offsets outside the table and strings that run past its end.
fn section_string(
  r : @core.Reader,
  tab : Shdr,
  off : Int64
) -> String raise ElfErr {
  if tab.typ == sht_nobits {
    raise ElfErr(bad("string table section is SHT_NOBITS"))
  }
  if off < 0 || off >= tab.size {
    raise ElfErr(bad("string offset outside string table"))
  }
  if !r.seek((tab.offset + off).to_int()) {
    raise ElfErr(trunc("string table seek"))
  }
  let s = need(r.cstring(), "unterminated string")
  if r.position().to_int64() > tab.offset + tab.size {
    raise ElfErr(bad("string runs past end of string table"))
  }
  s
}

/// Resolve a section's sh_link to its target section header.
fn linked_table(
  shdrs : Array[Shdr],
  s : Shdr,
  what : String
) -> Shdr raise ElfErr {
  if s.link < 0 || s.link >= shdrs.length().to_int64() {
    raise ElfErr(bad(what + ": sh_link out of range"))
  }
  shdrs[s.link.to_int()]
}

///|
fn parse_inner(r : @core.Reader) -> Elf raise ElfErr {
  let len64 = r.length().to_int64()
  // e_ident
  let magic = need(r.take(4), "e_ident magic")
  if magic[0].to_int() != 0x7F ||
    magic[1].to_int() != 0x45 ||
    magic[2].to_int() != 0x4C ||
    magic[3].to_int() != 0x46 {
    raise ElfErr(@core.ParseError::BadMagic("not an ELF file"))
  }
  let class = match need(r.u8(), "EI_CLASS") {
    1 => 32
    2 => 64
    _ => raise ElfErr(bad("EI_CLASS must be 1 (32-bit) or 2 (64-bit)"))
  }
  let endian = match need(r.u8(), "EI_DATA") {
    1 => @core.Endian::Little
    2 => @core.Endian::Big
    _ => raise ElfErr(bad("EI_DATA must be 1 (LSB) or 2 (MSB)"))
  }
  if need(r.u8(), "EI_VERSION") != 1 {
    raise ElfErr(bad("EI_VERSION must be 1"))
  }
  // EI_OSABI, EI_ABIVERSION and padding are accepted as-is.
  let _pad = need(r.take(9), "e_ident padding")
  // ELF header proper.
  let _e_type = need(r.u16(endian), "e_type")
  let machine = need(r.u16(endian), "e_machine").to_int()
  if need(r.u32(endian), "e_version") != 1 {
    raise ElfErr(bad("e_version must be 1"))
  }
  let entry = need(read_addr(r, endian, class), "e_entry")
  let phoff = need(read_addr(r, endian, class), "e_phoff")
  let shoff = need(read_addr(r, endian, class), "e_shoff")
  let _e_flags = need(r.u32(endian), "e_flags")
  let ehsize = need(r.u16(endian), "e_ehsize")
  let phentsize = need(r.u16(endian), "e_phentsize")
  let mut phnum = need(r.u16(endian), "e_phnum")
  let shentsize = need(r.u16(endian), "e_shentsize")
  let shnum = need(r.u16(endian), "e_shnum")
  let shstrndx = need(r.u16(endian), "e_shstrndx")
  let want_ehsize : Int64 = if class == 64 { 64 } else { 52 }
  if ehsize != want_ehsize {
    raise ElfErr(bad("e_ehsize does not match ELF class"))
  }
  let want_phentsize : Int64 = if class == 64 { 56 } else { 32 }
  if phoff < 0 || phoff > len64 {
    raise ElfErr(trunc("e_phoff out of range"))
  }
  // Section header table, with extended numbering (shnum == 0 / SHN_XINDEX /
  // PN_XNUM resolve through section header 0).
  let mut real_shnum = shnum
  let mut real_shstrndx = shstrndx
  if shoff != 0 {
    if shoff < 0 || shoff > len64 {
      raise ElfErr(trunc("e_shoff out of range"))
    }
    let want_shentsize : Int64 = if class == 64 { 64 } else { 40 }
    if shentsize != want_shentsize {
      raise ElfErr(bad("e_shentsize does not match ELF class"))
    }
    if !r.seek(shoff.to_int()) {
      raise ElfErr(trunc("section header 0"))
    }
    let sh0 = read_shdr(r, endian, class)
    if shnum == 0 {
      real_shnum = sh0.size
    }
    if shstrndx == shn_xindex {
      real_shstrndx = sh0.link
    }
    if phnum == pn_xnum {
      phnum = sh0.info
    }
  } else {
    if shnum != 0 {
      raise ElfErr(bad("e_shnum non-zero without e_shoff"))
    }
    if phnum == pn_xnum {
      raise ElfErr(bad("PN_XNUM without section headers"))
    }
  }
  if phnum > 0 {
    // Also covers the PN_XNUM path, where phnum was just resolved.
    if phentsize != want_phentsize {
      raise ElfErr(bad("e_phentsize does not match ELF class"))
    }
    if phnum > (len64 - phoff) / phentsize {
      raise ElfErr(trunc("program header table out of range"))
    }
  }
  if real_shnum < 0 ||
    (real_shnum > 0 && real_shnum > (len64 - shoff) / shentsize) {
    raise ElfErr(trunc("section header table out of range"))
  }
  if real_shstrndx < 0 || (real_shnum > 0 && real_shstrndx >= real_shnum) {
    raise ElfErr(bad("e_shstrndx out of range"))
  }
  let shnum_int = real_shnum.to_int()
  let phnum_int = phnum.to_int()
  let shdrs : Array[Shdr] = []
  if shnum_int > 0 {
    if !r.seek(shoff.to_int()) {
      raise ElfErr(trunc("section header table seek"))
    }
    for i = 0; i < shnum_int; i = i + 1 {
      shdrs.push(read_shdr(r, endian, class))
    }
  }
  // Section contents must lie inside the file (SHT_NOBITS has no file bytes;
  // SHT_NULL carries no contents, and in extended numbering its size field
  // holds the real section count).
  for s in shdrs {
    if s.typ != sht_nobits && s.typ != sht_null {
      if s.offset < 0 ||
        s.size < 0 ||
        s.offset > len64 ||
        s.size > len64 - s.offset {
        raise ElfErr(trunc("section contents out of range"))
      }
    }
  }
  let shstrtab : Shdr? = if real_shstrndx > 0 && shnum_int > 0 {
    Some(shdrs[real_shstrndx.to_int()])
  } else {
    None
  }
  let sections : Array[@core.Region] = []
  for s in shdrs {
    let name = match shstrtab {
      Some(tab) =>
        if s.name_off == 0 {
          ""
        } else {
          section_string(r, tab, s.name_off)
        }
      None => ""
    }
    sections.push(
      @core.Region::{
        name,
        offset: s.offset,
        size: s.size,
        vaddr: s.addr,
        flags: section_flags(s.flags),
      },
    )
  }
  // Program headers -> segments.
  let segments : Array[@core.Region] = []
  if phnum_int > 0 {
    if !r.seek(phoff.to_int()) {
      raise ElfErr(trunc("program header table seek"))
    }
    for i = 0; i < phnum_int; i = i + 1 {
      let p = read_phdr(r, endian, class)
      if p.filesz > 0 &&
        (p.offset < 0 ||
        p.filesz < 0 ||
        p.offset > len64 ||
        p.filesz > len64 - p.offset) {
        raise ElfErr(trunc("segment contents out of range"))
      }
      segments.push(
        @core.Region::{
          name: segment_name(p.typ),
          offset: p.offset,
          size: p.filesz,
          vaddr: p.vaddr,
          flags: segment_flags(p.flags),
        },
      )
    }
  }
  // Symbol tables.
  let symbols : Array[@core.Symbol] = []
  let exports : Array[@core.Export] = []
  let sym_want : Int64 = if class == 64 { 24 } else { 16 }
  for s in shdrs {
    if s.typ != sht_symtab && s.typ != sht_dynsym {
      continue
    }
    let is_dyn = s.typ == sht_dynsym
    let strtab = linked_table(shdrs, s, "symbol string table")
    let entsize = if s.entsize > 0 { s.entsize } else { sym_want }
    if entsize != sym_want {
      raise ElfErr(bad("symbol table entry size does not match ELF class"))
    }
    if s.size < 0 || (s.size % entsize) != 0 {
      raise ElfErr(bad("symbol table size is not a multiple of entry size"))
    }
    let count = (s.size / entsize).to_int()
    for i = 0; i < count; i = i + 1 {
      if !r.seek((s.offset + i.to_int64() * entsize).to_int()) {
        raise ElfErr(trunc("symbol table seek"))
      }
      let sym = read_sym(r, endian, class)
      // Skip the standard all-zero null entry at index 0.
      if i == 0 &&
        sym.name_off == 0 &&
        sym.value == 0 &&
        sym.size == 0 &&
        sym.info == 0 &&
        sym.shndx == 0 {
        continue
      }
      let name = if sym.name_off == 0 {
        ""
      } else {
        section_string(r, strtab, sym.name_off)
      }
      // SHN_UNDEF (0) and the special range (ABS / COMMON / XINDEX / ...)
      // are not real section indices.
      let shndx = if sym.shndx == 0 || sym.shndx >= 0xFF00 {
        -1
      } else {
        sym.shndx.to_int()
      }
      symbols.push(
        @core.Symbol::{
          name,
          value: sym.value,
          size: sym.size,
          kind: symbol_kind(sym.info & 0xF),
          bind: symbol_bind(sym.info >> 4),
          shndx,
        },
      )
      // Defined dynamic symbols are exports (SHN_ABS counts as defined).
      if is_dyn && sym.shndx != 0 && name != "" {
        exports.push(@core.Export::{ name, ordinal: 0, rva: sym.value })
      }
    }
  }
  // SHT_DYNAMIC: DT_NEEDED -> imports.
  let imports : Array[@core.Import] = []
  let dyn_want : Int64 = if class == 64 { 16 } else { 8 }
  for s in shdrs {
    if s.typ != sht_dynamic {
      continue
    }
    let strtab = linked_table(shdrs, s, "dynamic string table")
    let entsize = if s.entsize > 0 { s.entsize } else { dyn_want }
    if entsize != dyn_want {
      raise ElfErr(bad("dynamic entry size does not match ELF class"))
    }
    if s.size < 0 || (s.size % entsize) != 0 {
      raise ElfErr(bad("dynamic table size is not a multiple of entry size"))
    }
    let count = (s.size / entsize).to_int()
    for i = 0; i < count; i = i + 1 {
      if !r.seek((s.offset + i.to_int64() * entsize).to_int()) {
        raise ElfErr(trunc("dynamic table seek"))
      }
      let tag = need(read_addr(r, endian, class), "d_tag")
      let val = need(read_addr(r, endian, class), "d_val")
      if tag == dt_null {
        break
      }
      if tag == dt_needed {
        let library = section_string(r, strtab, val)
        imports.push(@core.Import::{ library, name: "" })
      }
    }
  }
  Elf::{
    class,
    endian,
    machine,
    entry,
    sections,
    segments,
    symbols,
    imports,
    exports,
  }
}

/// Parse an ELF image: header, program headers, section headers, symbol
/// tables (SHT_SYMTAB / SHT_DYNSYM) and SHT_DYNAMIC. Refuses malformed or
/// truncated input with `Err`; never panics.
pub fn parse(data : Bytes) -> Result[Elf, @core.ParseError] {
  try Ok(parse_inner(@core.Reader::new(data))) catch {
    ElfErr(e) => Err(e)
  }
}