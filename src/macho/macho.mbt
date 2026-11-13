/// Mach-O 32 / 64 parser, both endians. Pure and bounds-checked: malformed or
/// truncated input yields `Err`, never a panic and never a guess.
///
/// Supported load commands: LC_SEGMENT / LC_SEGMENT_64 (segments + sections),
/// LC_SYMTAB (nlist symbols + string table), LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB
/// (imported library names), LC_MAIN and LC_UNIXTHREAD (entry point). Other
/// load commands are skipped by their cmdsize. Defined symbols become exports.

/// Parsed Mach-O image metadata (see INTERFACES.md, frozen v0.1).
pub(all) struct MachO {
  /// 32 or 64 (from the magic).
  class : Int
  /// Byte order (from the magic).
  endian : @core.Endian
  /// cputype (e.g. 0x01000007 = x86-64, 18 = PowerPC).
  cpu : Int
  /// Entry virtual address. LC_MAIN's file offset is resolved through the
  /// segment that covers it; LC_UNIXTHREAD yields the thread-state PC.
  /// 0 when neither command is present.
  entry : Int64
  /// Sections from all LC_SEGMENT / LC_SEGMENT_64 commands, in order.
  sections : Array[@core.Region]
  /// Segments in load-command order.
  segments : Array[@core.Region]
  /// LC_SYMTAB nlist entries, in table order.
  symbols : Array[@core.Symbol]
  /// LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB library names.
  imports : Array[@core.Import]
  /// Defined (non-stab, non-undefined) symbols.
  exports : Array[@core.Export]
} derive(Debug)

/// Internal carrier so helpers can `raise` and `parse` converts to `Result`.
priv suberror MachOErr {
  MachOErr(@core.ParseError)
}

// Load command ids.
let lc_segment : Int64 = 0x1
let lc_symtab : Int64 = 0x2
let lc_unixthread : Int64 = 0x5
let lc_load_dylib : Int64 = 0xC
let lc_load_weak_dylib : Int64 = 0x18
let lc_segment_64 : Int64 = 0x19
let lc_main : Int64 = 0x80000028

// CPU types (cpu_type_t).
let cpu_x86 : Int64 = 7
let cpu_x86_64 : Int64 = 0x01000007
let cpu_arm : Int64 = 12
let cpu_arm64 : Int64 = 0x0100000C
let cpu_ppc : Int64 = 18
let cpu_ppc64 : Int64 = 0x01000012

// nlist n_type bits.
let n_stab : Int64 = 0xE0
let n_pext : Int64 = 0x10
let n_type : Int64 = 0x0E
let n_ext : Int64 = 0x01
// n_desc weak bits (N_WEAK_REF 0x0040 | N_WEAK_DEF 0x0080).
let n_weak : Int64 = 0x00C0

///|
fn trunc(what : String) -> @core.ParseError {
  @core.ParseError::Truncated(what)
}

///|
fn bad(what : String) -> @core.ParseError {
  @core.ParseError::Invalid(what)
}

///|
fn[T] need(opt : T?, what : String) -> T raise MachOErr {
  match opt {
    Some(v) => v
    None => raise MachOErr(trunc(what))
  }
}

///|
fn read_addr(r : @core.Reader, endian : @core.Endian, is64 : Bool) -> Int64? {
  if is64 {
    r.u64(endian)
  } else {
    r.u32(endian)
  }
}

/// VM protection bits -> "rwx": VM_PROT_READ = 1, WRITE = 2, EXECUTE = 4.
fn prot_flags(p : Int64) -> String {
  let mut out = ""
  if (p & 1) != 0 {
    out = out + "r"
  }
  if (p & 2) != 0 {
    out = out + "w"
  }
  if (p & 4) != 0 {
    out = out + "x"
  }
  out
}

/// Read a fixed-width, NUL-padded name field (segment / section names).
fn fixed_name(r : @core.Reader, n : Int) -> String raise MachOErr {
  let b = need(r.take(n), "fixed name field")
  let chars : Array[Char] = []
  for i = 0; i < n; i = i + 1 {
    let c = b[i].to_int()
    if c == 0 {
      break
    }
    chars.push(c.unsafe_to_char())
  }
  String::from_array(chars)
}

/// nlist type -> kind vocabulary.
fn sym_kind(t : Int64) -> String {
  if (t & n_stab) != 0 {
    return "debug"
  }
  match t & n_type {
    0x0 => "undefined"
    0x2 => "absolute"
    0xE => "section"
    0xC => "prebound"
    0xA => "indirect"
    _ => "unknown"
  }
}

/// nlist type + desc -> binding vocabulary.
fn sym_bind(t : Int64, desc : Int64) -> String {
  if (t & n_ext) == 0 {
    "local"
  } else if (t & n_pext) != 0 {
    "private"
  } else if (desc & n_weak) != 0 {
    "weak"
  } else {
    "global"
  }
}

/// Read a NUL-terminated string from the symbol string table, refusing
/// offsets outside the table and strings that run past its end.
fn strtab_string(
  r : @core.Reader,
  stroff : Int64,
  strsize : Int64,
  strx : Int64
) -> String raise MachOErr {
  if strx < 0 || strx >= strsize {
    raise MachOErr(bad("symbol string offset outside string table"))
  }
  if !r.seek((stroff + strx).to_int()) {
    raise MachOErr(trunc("string table seek"))
  }
  let s = need(r.cstring(), "unterminated symbol string")
  if r.position().to_int64() > stroff + strsize {
    raise MachOErr(bad("symbol string runs past end of string table"))
  }
  s
}

/// Parse LC_SEGMENT / LC_SEGMENT_64: the segment plus its sections. The
/// command id (not the file class) dictates 32- vs 64-bit field widths.
fn parse_segment(
  r : @core.Reader,
  endian : @core.Endian,
  is64 : Bool,
  cmdsize : Int64,
  len64 : Int64,
  segments : Array[@core.Region],
  sections : Array[@core.Region]
) -> Unit raise MachOErr {
  let seg_hdr : Int64 = if is64 { 72 } else { 56 }
  let sec_size : Int64 = if is64 { 80 } else { 68 }
  if cmdsize < seg_hdr {
    raise MachOErr(bad("segment command smaller than its header"))
  }
  let segname = fixed_name(r, 16)
  let vmaddr = need(read_addr(r, endian, is64), "segment vmaddr")
  let _vmsize = need(read_addr(r, endian, is64), "segment vmsize")
  let fileoff = need(read_addr(r, endian, is64), "segment fileoff")
  let filesize = need(read_addr(r, endian, is64), "segment filesize")
  let _maxprot = need(r.u32(endian), "segment maxprot")
  let initprot = need(r.u32(endian), "segment initprot")
  let nsects = need(r.u32(endian), "segment nsects")
  let _flags = need(r.u32(endian), "segment flags")
  if seg_hdr + nsects * sec_size > cmdsize {
    raise MachOErr(bad("segment sections exceed command size"))
  }
  if filesize > 0 && (fileoff > len64 || filesize > len64 - fileoff) {
    raise MachOErr(trunc("segment contents out of range"))
  }
  let flags = prot_flags(initprot)
  segments.push(
    @core.Region::{ name: segname, offset: fileoff, size: filesize, vaddr: vmaddr, flags },
  )
  let nsects_int = nsects.to_int()
  for j = 0; j < nsects_int; j = j + 1 {
    let sectname = fixed_name(r, 16)
    let _segname = fixed_name(r, 16)
    let addr = need(read_addr(r, endian, is64), "section addr")
    let size = need(read_addr(r, endian, is64), "section size")
    let offset = need(r.u32(endian), "section offset")
    let _align = need(r.u32(endian), "section align")
    let _reloff = need(r.u32(endian), "section reloff")
    let _nreloc = need(r.u32(endian), "section nreloc")
    let sflags = need(r.u32(endian), "section flags")
    let _reserved1 = need(r.u32(endian), "section reserved1")
    let _reserved2 = need(r.u32(endian), "section reserved2")
    if is64 {
      let _reserved3 = need(r.u32(endian), "section reserved3")
    }
    // S_ZEROFILL (1) and S_THREAD_LOCAL_ZEROFILL (0x12) carry no file bytes.
    let stype = sflags & 0xFF
    let zerofill = stype == 1 || stype == 0x12
    if !zerofill && (offset > len64 || size > len64 - offset) {
      raise MachOErr(trunc("section contents out of range"))
    }
    sections.push(
      @core.Region::{ name: sectname, offset, size, vaddr: addr, flags },
    )
  }
}

/// Parse LC_SYMTAB: nlist entries resolved against the string table.
fn parse_symtab(
  r : @core.Reader,
  endian : @core.Endian,
  class : Int,
  cmdsize : Int64,
  len64 : Int64,
  symbols : Array[@core.Symbol],
  exports : Array[@core.Export]
) -> Unit raise MachOErr {
  if cmdsize < 24 {
    raise MachOErr(bad("LC_SYMTAB command smaller than its header"))
  }
  let nlist_size : Int64 = if class == 64 { 16 } else { 12 }
  let symoff = need(r.u32(endian), "symtab symoff")
  let nsyms = need(r.u32(endian), "symtab nsyms")
  let stroff = need(r.u32(endian), "symtab stroff")
  let strsize = need(r.u32(endian), "symtab strsize")
  if symoff > len64 || nsyms * nlist_size > len64 - symoff {
    raise MachOErr(trunc("symbol table out of range"))
  }
  if stroff > len64 || strsize > len64 - stroff {
    raise MachOErr(trunc("string table out of range"))
  }
  let nsyms_int = nsyms.to_int()
  for k = 0; k < nsyms_int; k = k + 1 {
    if !r.seek((symoff + k.to_int64() * nlist_size).to_int()) {
      raise MachOErr(trunc("symbol table seek"))
    }
    let strx = need(r.u32(endian), "nlist n_strx")
    let nt = need(r.u8(), "nlist n_type").to_int64()
    let nsect = need(r.u8(), "nlist n_sect").to_int64()
    let ndesc = need(r.u16(endian), "nlist n_desc")
    let value = need(read_addr(r, endian, class == 64), "nlist n_value")
    let name = if strx == 0 {
      ""
    } else {
      strtab_string(r, stroff, strsize, strx)
    }
    let shndx = if nsect == 0 { -1 } else { nsect.to_int() }
    symbols.push(
      @core.Symbol::{
        name,
        value,
        size: 0,
        kind: sym_kind(nt),
        bind: sym_bind(nt, ndesc),
        shndx,
      },
    )
    // Defined, non-stab symbols are exports.
    if (nt & n_stab) == 0 && (nt & n_type) != 0 && name != "" {
      exports.push(@core.Export::{ name, ordinal: 0, rva: value })
    }
  }
}

/// Parse LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB: the imported library name.
fn parse_dylib(
  r : @core.Reader,
  endian : @core.Endian,
  cmdsize : Int64,
  cmd_start : Int64,
  imports : Array[@core.Import]
) -> Unit raise MachOErr {
  if cmdsize < 24 {
    raise MachOErr(bad("dylib command smaller than its header"))
  }
  let name_off = need(r.u32(endian), "dylib name offset")
  let _timestamp = need(r.u32(endian), "dylib timestamp")
  let _current_version = need(r.u32(endian), "dylib current_version")
  let _compatibility_version = need(r.u32(endian), "dylib compatibility_version")
  if name_off < 24 || name_off >= cmdsize {
    raise MachOErr(bad("dylib name offset out of range"))
  }
  if !r.seek((cmd_start + name_off).to_int()) {
    raise MachOErr(trunc("dylib name seek"))
  }
  let library = need(r.cstring(), "unterminated dylib name")
  if r.position().to_int64() > cmd_start + cmdsize {
    raise MachOErr(bad("dylib name runs past end of command"))
  }
  imports.push(@core.Import::{ library, name: "" })
}

/// Read a u32 PC field at word index `idx` of the thread state.
fn thread_pc_u32(
  r : @core.Reader,
  endian : @core.Endian,
  state_start : Int64,
  count : Int64,
  idx : Int64
) -> Int64 raise MachOErr {
  if idx + 1 > count {
    raise MachOErr(bad("unixthread state too short for PC"))
  }
  if !r.seek((state_start + idx * 4).to_int()) {
    raise MachOErr(trunc("unixthread PC seek"))
  }
  need(r.u32(endian), "unixthread PC")
}

/// Read a u64 PC field starting at u32 word index `idx` of the thread state
/// (the field spans words `idx` and `idx + 1`).
fn thread_pc_u64(
  r : @core.Reader,
  endian : @core.Endian,
  state_start : Int64,
  count : Int64,
  idx : Int64
) -> Int64 raise MachOErr {
  if idx + 2 > count {
    raise MachOErr(bad("unixthread state too short for PC"))
  }
  if !r.seek((state_start + idx * 4).to_int()) {
    raise MachOErr(trunc("unixthread PC seek"))
  }
  need(r.u64(endian), "unixthread PC")
}

/// Parse LC_UNIXTHREAD: extract the PC from the architecture's thread state.
/// Unknown cputype / flavor combinations are refused, never guessed.
fn parse_unixthread(
  r : @core.Reader,
  endian : @core.Endian,
  cpu : Int,
  cmdsize : Int64,
  cmd_start : Int64
) -> Int64 raise MachOErr {
  if cmdsize < 16 {
    raise MachOErr(bad("LC_UNIXTHREAD command smaller than its header"))
  }
  let flavor = need(r.u32(endian), "unixthread flavor")
  let count = need(r.u32(endian), "unixthread count")
  if 16L + count * 4 > cmdsize {
    raise MachOErr(bad("unixthread state exceeds command size"))
  }
  let state_start = cmd_start + 16
  let cputype = cpu.to_int64()
  if cputype == cpu_x86 || cputype == cpu_x86_64 {
    if flavor == 4 {
      // x86_THREAD_STATE64: rip is the 17th u64 (u32 word index 32).
      thread_pc_u64(r, endian, state_start, count, 32)
    } else if flavor == 1 || flavor == 7 {
      // x86_THREAD_STATE32: eip is the 11th u32 (word index 10).
      thread_pc_u32(r, endian, state_start, count, 10)
    } else {
      raise MachOErr(bad("unsupported x86 unixthread flavor"))
    }
  } else if cputype == cpu_arm {
    if flavor == 1 {
      // ARM_THREAD_STATE: pc is the 16th u32 (word index 15).
      thread_pc_u32(r, endian, state_start, count, 15)
    } else {
      raise MachOErr(bad("unsupported ARM unixthread flavor"))
    }
  } else if cputype == cpu_arm64 {
    if flavor == 6 {
      // ARM_THREAD_STATE64: pc is the 33rd u64 (u32 word index 64).
      thread_pc_u64(r, endian, state_start, count, 64)
    } else {
      raise MachOErr(bad("unsupported ARM64 unixthread flavor"))
    }
  } else if cputype == cpu_ppc {
    if flavor == 1 {
      // PPC_THREAD_STATE: srr0 is the first u32.
      thread_pc_u32(r, endian, state_start, count, 0)
    } else {
      raise MachOErr(bad("unsupported PPC unixthread flavor"))
    }
  } else if cputype == cpu_ppc64 {
    if flavor == 5 {
      // PPC_THREAD_STATE64: srr0 is the first u64.
      thread_pc_u64(r, endian, state_start, count, 0)
    } else {
      raise MachOErr(bad("unsupported PPC64 unixthread flavor"))
    }
  } else {
    raise MachOErr(bad("unsupported cputype for LC_UNIXTHREAD"))
  }
}

/// Resolve a LC_MAIN file offset to a virtual address through the segment
/// that covers it. Falls back to the raw offset when no segment covers it.
fn resolve_entry_va(off : Int64, segments : Array[@core.Region]) -> Int64 {
  for s in segments {
    if s.size > 0 && off >= s.offset && off < s.offset + s.size {
      return s.vaddr + (off - s.offset)
    }
  }
  off
}

///|
fn parse_inner(r : @core.Reader) -> MachO raise MachOErr {
  let len64 = r.length().to_int64()
  // Read the magic as big-endian to classify class + byte order at once.
  let magic = need(r.u32(@core.Endian::Big), "mach magic")
  let (class, endian) = match magic {
    0xFEEDFACE => (32, @core.Endian::Big)
    0xFEEDFACF => (64, @core.Endian::Big)
    0xCEFAEDFE => (32, @core.Endian::Little)
    0xCFFAEDFE => (64, @core.Endian::Little)
    _ => raise MachOErr(@core.ParseError::BadMagic("not a Mach-O file"))
  }
  let cpu = need(r.u32(endian), "cputype").to_int()
  let _cpusubtype = need(r.u32(endian), "cpusubtype")
  let _filetype = need(r.u32(endian), "filetype")
  let ncmds = need(r.u32(endian), "ncmds")
  let sizeofcmds = need(r.u32(endian), "sizeofcmds")
  let _flags = need(r.u32(endian), "flags")
  if class == 64 {
    let _reserved = need(r.u32(endian), "mach_header_64 reserved")
  }
  let hdr_size : Int64 = if class == 64 { 32 } else { 28 }
  if hdr_size + sizeofcmds > len64 {
    raise MachOErr(trunc("load commands out of range"))
  }
  if ncmds > sizeofcmds / 8 {
    raise MachOErr(bad("ncmds exceeds the load command area"))
  }
  let cmd_region_end = hdr_size + sizeofcmds
  let ncmds_int = ncmds.to_int()
  let segments : Array[@core.Region] = []
  let sections : Array[@core.Region] = []
  let symbols : Array[@core.Symbol] = []
  let imports : Array[@core.Import] = []
  let exports : Array[@core.Export] = []
  let mut main_off : Int64? = None
  let mut thread_pc : Int64? = None
  let mut pos = hdr_size
  for i = 0; i < ncmds_int; i = i + 1 {
    if !r.seek(pos.to_int()) {
      raise MachOErr(trunc("load command seek"))
    }
    let cmd = need(r.u32(endian), "load command cmd")
    let cmdsize = need(r.u32(endian), "load command cmdsize")
    if cmdsize < 8 {
      raise MachOErr(bad("load command cmdsize < 8"))
    }
    let cmd_end = pos + cmdsize
    if cmd_end > cmd_region_end {
      raise MachOErr(bad("load command extends past sizeofcmds"))
    }
    if cmd == lc_segment || cmd == lc_segment_64 {
      parse_segment(r, endian, cmd == lc_segment_64, cmdsize, len64, segments, sections)
    } else if cmd == lc_symtab {
      parse_symtab(r, endian, class, cmdsize, len64, symbols, exports)
    } else if cmd == lc_load_dylib || cmd == lc_load_weak_dylib {
      parse_dylib(r, endian, cmdsize, pos, imports)
    } else if cmd == lc_main {
      if cmdsize < 24 {
        raise MachOErr(bad("LC_MAIN command smaller than its header"))
      }
      let off = need(r.u64(endian), "LC_MAIN entryoff")
      if off >= len64 {
        raise MachOErr(bad("LC_MAIN entryoff out of range"))
      }
      if main_off is None {
        main_off = Some(off)
      }
    } else if cmd == lc_unixthread {
      if thread_pc is None {
        thread_pc = Some(parse_unixthread(r, endian, cpu, cmdsize, pos))
      }
    }
    // Unknown load commands are skipped by cmdsize.
    pos = cmd_end
  }
  // LC_MAIN takes precedence over LC_UNIXTHREAD (dyld semantics).
  let entry = match main_off {
    Some(off) => resolve_entry_va(off, segments)
    None =>
      match thread_pc {
        Some(pc) => pc
        None => 0
      }
  }
  MachO::{
    class,
    endian,
    cpu,
    entry,
    sections,
    segments,
    symbols,
    imports,
    exports,
  }
}

/// Parse a Mach-O image: header, segments + sections, symbol table, imported
/// dylibs and the entry point. Refuses malformed or truncated input with
/// `Err`; never panics.
pub fn parse(data : Bytes) -> Result[MachO, @core.ParseError] {
  try Ok(parse_inner(@core.Reader::new(data))) catch {
    MachOErr(e) => Err(e)
  }
}