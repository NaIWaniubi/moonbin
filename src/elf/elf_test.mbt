// Deterministic in-test ELF fixtures + golden assertions.
//
// build_elf(class, endian) crafts a complete, valid ELF with:
//   sections [0]=NULL [1]=.text [2]=.symtab [3]=.strtab [4]=.dynsym
//            [5]=.dynstr [6]=.dynamic [7]=.shstrtab
//   program headers: PT_LOAD (whole file) + PT_DYNAMIC (.dynamic section)
//   .symtab: null + "main" (FUNC GLOBAL) + "helper" (OBJECT GLOBAL)
//   .dynsym: null + "printf" (FUNC GLOBAL, undefined) +
//            "moonbin_version" (OBJECT GLOBAL, defined)
//   .dynamic: DT_NEEDED "libc.so.6", DT_STRTAB, DT_NULL
// The exact same bytes are dumped as hex by the "crosscheck dump" test and
// verified against GNU readelf by test/elf_crosscheck.sh.

///|
fn put_int(
  buf : Array[Byte],
  v : Int64,
  width : Int,
  endian : @core.Endian
) -> Unit {
  for i = 0; i < width; i = i + 1 {
    let shift = match endian {
      @core.Endian::Little => i * 8
      @core.Endian::Big => (width - 1 - i) * 8
    }
    buf.push(((v >> shift) & 0xFF).to_int().to_byte())
  }
}

///|
fn patch_int(
  buf : Array[Byte],
  at : Int,
  v : Int64,
  width : Int,
  endian : @core.Endian
) -> Unit {
  for i = 0; i < width; i = i + 1 {
    let shift = match endian {
      @core.Endian::Little => i * 8
      @core.Endian::Big => (width - 1 - i) * 8
    }
    buf[at + i] = ((v >> shift) & 0xFF).to_int().to_byte()
  }
}

///|
fn patch_phdr(
  buf : Array[Byte],
  at : Int,
  class : Int,
  endian : @core.Endian,
  typ : Int64,
  flags : Int64,
  off : Int64,
  vaddr : Int64,
  filesz : Int64,
  align : Int64
) -> Unit {
  let aw = if class == 64 { 8 } else { 4 }
  patch_int(buf, at, typ, 4, endian)
  if class == 64 {
    patch_int(buf, at + 4, flags, 4, endian)
    patch_int(buf, at + 8, off, aw, endian)
    patch_int(buf, at + 8 + aw, vaddr, aw, endian)
    patch_int(buf, at + 8 + 2 * aw, vaddr, aw, endian)
    patch_int(buf, at + 8 + 3 * aw, filesz, aw, endian)
    patch_int(buf, at + 8 + 4 * aw, filesz, aw, endian)
    patch_int(buf, at + 8 + 5 * aw, align, aw, endian)
  } else {
    patch_int(buf, at + 4, off, aw, endian)
    patch_int(buf, at + 4 + aw, vaddr, aw, endian)
    patch_int(buf, at + 4 + 2 * aw, vaddr, aw, endian)
    patch_int(buf, at + 4 + 3 * aw, filesz, aw, endian)
    patch_int(buf, at + 4 + 4 * aw, filesz, aw, endian)
    patch_int(buf, at + 4 + 5 * aw, flags, 4, endian)
    patch_int(buf, at + 4 + 6 * aw, align, aw, endian)
  }
}

///|
fn put_zeros(buf : Array[Byte], n : Int) -> Unit {
  for i = 0; i < n; i = i + 1 {
    buf.push((0 : Int).to_byte())
  }
}

///|
fn put_str(buf : Array[Byte], s : String) -> Unit {
  for c in s {
    buf.push(c.to_int().to_byte())
  }
  buf.push((0 : Int).to_byte())
}

///|
fn put_sym(
  buf : Array[Byte],
  class : Int,
  endian : @core.Endian,
  name_off : Int64,
  info : Int,
  shndx : Int,
  value : Int64,
  size : Int64
) -> Unit {
  put_int(buf, name_off, 4, endian)
  if class == 64 {
    put_int(buf, info.to_int64(), 1, endian)
    put_int(buf, 0, 1, endian)
    put_int(buf, shndx.to_int64(), 2, endian)
    put_int(buf, value, 8, endian)
    put_int(buf, size, 8, endian)
  } else {
    put_int(buf, value, 4, endian)
    put_int(buf, size, 4, endian)
    put_int(buf, info.to_int64(), 1, endian)
    put_int(buf, 0, 1, endian)
    put_int(buf, shndx.to_int64(), 2, endian)
  }
}

///|
fn put_shdr(
  buf : Array[Byte],
  class : Int,
  endian : @core.Endian,
  name_off : Int64,
  typ : Int64,
  flags : Int64,
  addr : Int64,
  off : Int64,
  size : Int64,
  link : Int64,
  info : Int64,
  align : Int64,
  entsize : Int64
) -> Unit {
  let aw = if class == 64 { 8 } else { 4 }
  put_int(buf, name_off, 4, endian)
  put_int(buf, typ, 4, endian)
  put_int(buf, flags, aw, endian)
  put_int(buf, addr, aw, endian)
  put_int(buf, off, aw, endian)
  put_int(buf, size, aw, endian)
  put_int(buf, link, 4, endian)
  put_int(buf, info, 4, endian)
  put_int(buf, align, aw, endian)
  put_int(buf, entsize, aw, endian)
}

///|
fn build_elf(class : Int, endian : @core.Endian) -> Bytes {
  let aw = if class == 64 { 8 } else { 4 }
  let ehsize = if class == 64 { 64 } else { 52 }
  let phentsize = if class == 64 { 56 } else { 32 }
  let shentsize = if class == 64 { 64 } else { 40 }
  let sym_es = if class == 64 { 24 } else { 16 }
  let dyn_es = if class == 64 { 16 } else { 8 }
  let machine = if class == 64 { 62 } else { 20 }
  let base : Int64 = if class == 64 { 0x400000 } else { 0x01000000 }
  let text_addr = base + 0x1000
  let buf : Array[Byte] = []
  // ELF header (patched at the end once all offsets are known).
  put_zeros(buf, ehsize)
  let phoff = buf.length()
  // Two program headers (PT_LOAD + PT_DYNAMIC), patched at the end once
  // all offsets are known.
  put_zeros(buf, 2 * phentsize)
  // .text: push rbp; mov rbp, rsp
  let text_off = buf.length()
  buf.push((0x55 : Int).to_byte())
  buf.push((0x48 : Int).to_byte())
  buf.push((0x89 : Int).to_byte())
  buf.push((0xE5 : Int).to_byte())
  // .symtab: null + main + helper
  let symtab_off = buf.length()
  put_zeros(buf, sym_es)
  put_sym(buf, class, endian, 1, 0x12, 1, text_addr, 4)
  put_sym(buf, class, endian, 6, 0x11, 1, text_addr + 4, 8)
  // .strtab: "\0main\0helper\0"
  let strtab_off = buf.length()
  put_str(buf, "")
  put_str(buf, "main")
  put_str(buf, "helper")
  let strtab_size = buf.length() - strtab_off
  // .dynsym: null + printf (undefined) + moonbin_version (defined)
  let dynsym_off = buf.length()
  put_zeros(buf, sym_es)
  put_sym(buf, class, endian, 1, 0x12, 0, 0, 0)
  put_sym(buf, class, endian, 8, 0x11, 1, base + 0x2000, 4)
  // .dynstr: "\0printf\0moonbin_version\0libc.so.6\0"
  let dynstr_off = buf.length()
  put_str(buf, "")
  put_str(buf, "printf")
  put_str(buf, "moonbin_version")
  put_str(buf, "libc.so.6")
  let dynstr_size = buf.length() - dynstr_off
  // .dynamic: DT_NEEDED(libc.so.6), DT_STRTAB, DT_NULL
  let dyn_off = buf.length()
  put_int(buf, 1, dyn_es / 2, endian)
  put_int(buf, 24, dyn_es / 2, endian)
  put_int(buf, 5, dyn_es / 2, endian)
  put_int(buf, base + 0x3000, dyn_es / 2, endian)
  put_int(buf, 0, dyn_es / 2, endian)
  put_int(buf, 0, dyn_es / 2, endian)
  // .shstrtab
  let shstrtab_off = buf.length()
  put_str(buf, "")
  put_str(buf, ".text")
  put_str(buf, ".symtab")
  put_str(buf, ".strtab")
  put_str(buf, ".dynsym")
  put_str(buf, ".dynstr")
  put_str(buf, ".dynamic")
  put_str(buf, ".shstrtab")
  let shstrtab_size = buf.length() - shstrtab_off
  // Section header table.
  let shoff = buf.length()
  put_zeros(buf, shentsize) // [0] SHT_NULL
  put_shdr(buf, class, endian, 1, 1, 6, text_addr, text_off.to_int64(), 4, 0, 0, 16, 0)
  put_shdr(buf, class, endian, 7, 2, 0, 0, symtab_off.to_int64(), (3 * sym_es).to_int64(), 3, 1, 8, sym_es.to_int64())
  put_shdr(buf, class, endian, 15, 3, 0, 0, strtab_off.to_int64(), strtab_size.to_int64(), 0, 0, 1, 0)
  put_shdr(buf, class, endian, 23, 11, 2, base + 0x2000, dynsym_off.to_int64(), (3 * sym_es).to_int64(), 5, 1, 8, sym_es.to_int64())
  put_shdr(buf, class, endian, 31, 3, 2, base + 0x3000, dynstr_off.to_int64(), dynstr_size.to_int64(), 0, 0, 1, 0)
  put_shdr(buf, class, endian, 39, 6, 3, base + 0x4000, dyn_off.to_int64(), (3 * dyn_es).to_int64(), 5, 0, 8, dyn_es.to_int64())
  put_shdr(buf, class, endian, 48, 3, 0, 0, shstrtab_off.to_int64(), shstrtab_size.to_int64(), 0, 0, 1, 0)
  let total = buf.length().to_int64()
  // PT_LOAD: R+X, whole file. PT_DYNAMIC: R+W, the .dynamic section.
  patch_phdr(buf, phoff, class, endian, 1, 5, 0, base, total, 0x1000)
  patch_phdr(buf, phoff + phentsize, class, endian, 2, 6, dyn_off.to_int64(), base + 0x4000, (3 * dyn_es).to_int64(), 8)
  // ELF header ident + fields.
  buf[0] = (0x7F : Int).to_byte()
  buf[1] = (0x45 : Int).to_byte()
  buf[2] = (0x4C : Int).to_byte()
  buf[3] = (0x46 : Int).to_byte()
  let class_byte : Int = if class == 64 { 2 } else { 1 }
  buf[4] = class_byte.to_byte()
  let data_byte : Int = match endian {
    @core.Endian::Little => 1
    @core.Endian::Big => 2
  }
  buf[5] = data_byte.to_byte()
  buf[6] = (1 : Int).to_byte() // EV_CURRENT
  patch_int(buf, 16, 2, 2, endian) // e_type = ET_EXEC
  patch_int(buf, 18, machine.to_int64(), 2, endian)
  patch_int(buf, 20, 1, 4, endian) // e_version
  patch_int(buf, 24, text_addr, aw, endian) // e_entry
  patch_int(buf, 24 + aw, phoff.to_int64(), aw, endian) // e_phoff
  patch_int(buf, 24 + 2 * aw, shoff.to_int64(), aw, endian) // e_shoff
  patch_int(buf, 24 + 3 * aw, 0, 4, endian) // e_flags
  patch_int(buf, 28 + 3 * aw, ehsize.to_int64(), 2, endian)
  patch_int(buf, 30 + 3 * aw, phentsize.to_int64(), 2, endian)
  patch_int(buf, 32 + 3 * aw, 2, 2, endian) // e_phnum
  patch_int(buf, 34 + 3 * aw, shentsize.to_int64(), 2, endian)
  patch_int(buf, 36 + 3 * aw, 8, 2, endian) // e_shnum
  patch_int(buf, 38 + 3 * aw, 7, 2, endian) // e_shstrndx
  Bytes::from_array(buf)
}

///|
fn patched_int(
  data : Bytes,
  at : Int,
  v : Int64,
  width : Int,
  endian : @core.Endian
) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i >= at && i < at + width {
      let k = i - at
      let shift = match endian {
        @core.Endian::Little => k * 8
        @core.Endian::Big => (width - 1 - k) * 8
      }
      ((v >> shift) & 0xFF).to_int().to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn hex_digit(v : Int) -> Char {
  Char::from_int(if v < 10 { 48 + v } else { 87 + v })
}

///|
fn to_hex(data : Bytes) -> String {
  let chars : Array[Char] = []
  for i = 0; i < data.length(); i = i + 1 {
    let b = data[i].to_int()
    chars.push(hex_digit(b >> 4))
    chars.push(hex_digit(b & 15))
  }
  String::from_array(chars)
}

test "elf64 little-endian golden parse" {
  let bytes = build_elf(64, @core.Endian::Little)
  let elf = @elf.parse(bytes).unwrap()
  assert_eq(elf.class, 64)
  assert_eq(elf.endian, @core.Endian::Little)
  assert_eq(elf.machine, 62)
  assert_eq(elf.entry, 0x401000)
  // Section table: names, offsets, sizes, flags.
  assert_eq(elf.sections.length(), 8)
  assert_eq(elf.sections[0].name, "")
  assert_eq(elf.sections[1].name, ".text")
  assert_eq(elf.sections[2].name, ".symtab")
  assert_eq(elf.sections[3].name, ".strtab")
  assert_eq(elf.sections[4].name, ".dynsym")
  assert_eq(elf.sections[5].name, ".dynstr")
  assert_eq(elf.sections[6].name, ".dynamic")
  assert_eq(elf.sections[7].name, ".shstrtab")
  assert_eq(elf.sections[1].offset, 176)
  assert_eq(elf.sections[1].size, 4)
  assert_eq(elf.sections[1].vaddr, 0x401000)
  assert_eq(elf.sections[1].flags, "rx")
  assert_eq(elf.sections[4].flags, "r")
  assert_eq(elf.sections[6].flags, "rw")
  assert_eq(elf.sections[2].flags, "")
  // Program headers: PT_LOAD then PT_DYNAMIC.
  assert_eq(elf.segments.length(), 2)
  assert_eq(elf.segments[0].name, "LOAD")
  assert_eq(elf.segments[0].offset, 0)
  assert_eq(elf.segments[0].vaddr, 0x400000)
  assert_eq(elf.segments[0].size, bytes.length().to_int64())
  assert_eq(elf.segments[0].flags, "rx")
  assert_eq(elf.segments[1].name, "DYNAMIC")
  assert_eq(elf.segments[1].offset, elf.sections[6].offset)
  assert_eq(elf.segments[1].vaddr, 0x404000)
  assert_eq(elf.segments[1].size, 48)
  assert_eq(elf.segments[1].flags, "rw")
  // Symbols: .symtab first, then .dynsym; null entries skipped.
  assert_eq(elf.symbols.length(), 4)
  assert_eq(elf.symbols[0].name, "main")
  assert_eq(elf.symbols[0].value, 0x401000)
  assert_eq(elf.symbols[0].size, 4)
  assert_eq(elf.symbols[0].kind, "func")
  assert_eq(elf.symbols[0].bind, "global")
  assert_eq(elf.symbols[0].shndx, 1)
  assert_eq(elf.symbols[1].name, "helper")
  assert_eq(elf.symbols[1].value, 0x401004)
  assert_eq(elf.symbols[1].size, 8)
  assert_eq(elf.symbols[1].kind, "object")
  assert_eq(elf.symbols[1].bind, "global")
  assert_eq(elf.symbols[2].name, "printf")
  assert_eq(elf.symbols[2].value, 0)
  assert_eq(elf.symbols[2].kind, "func")
  assert_eq(elf.symbols[2].shndx, -1)
  assert_eq(elf.symbols[3].name, "moonbin_version")
  assert_eq(elf.symbols[3].value, 0x402000)
  assert_eq(elf.symbols[3].size, 4)
  assert_eq(elf.symbols[3].shndx, 1)
  // Dynamic: DT_NEEDED -> imports, defined dynsym -> exports.
  assert_eq(elf.imports.length(), 1)
  assert_eq(elf.imports[0].library, "libc.so.6")
  assert_eq(elf.exports.length(), 1)
  assert_eq(elf.exports[0].name, "moonbin_version")
  assert_eq(elf.exports[0].rva, 0x402000)
}

test "elf32 big-endian golden parse" {
  let bytes = build_elf(32, @core.Endian::Big)
  let elf = @elf.parse(bytes).unwrap()
  assert_eq(elf.class, 32)
  assert_eq(elf.endian, @core.Endian::Big)
  assert_eq(elf.machine, 20)
  assert_eq(elf.entry, 0x01001000)
  assert_eq(elf.sections.length(), 8)
  assert_eq(elf.sections[1].name, ".text")
  assert_eq(elf.sections[2].name, ".symtab")
  assert_eq(elf.sections[3].name, ".strtab")
  assert_eq(elf.sections[4].name, ".dynsym")
  assert_eq(elf.sections[5].name, ".dynstr")
  assert_eq(elf.sections[6].name, ".dynamic")
  assert_eq(elf.sections[7].name, ".shstrtab")
  assert_eq(elf.sections[1].offset, 116)
  assert_eq(elf.sections[1].size, 4)
  assert_eq(elf.sections[1].vaddr, 0x01001000)
  assert_eq(elf.sections[1].flags, "rx")
  assert_eq(elf.sections[6].flags, "rw")
  assert_eq(elf.segments.length(), 2)
  assert_eq(elf.segments[0].name, "LOAD")
  assert_eq(elf.segments[0].vaddr, 0x01000000)
  assert_eq(elf.segments[0].size, bytes.length().to_int64())
  assert_eq(elf.segments[0].flags, "rx")
  assert_eq(elf.segments[1].name, "DYNAMIC")
  assert_eq(elf.segments[1].offset, elf.sections[6].offset)
  assert_eq(elf.segments[1].vaddr, 0x01004000)
  assert_eq(elf.segments[1].size, 24)
  assert_eq(elf.segments[1].flags, "rw")
  assert_eq(elf.symbols.length(), 4)
  assert_eq(elf.symbols[0].name, "main")
  assert_eq(elf.symbols[0].value, 0x01001000)
  assert_eq(elf.symbols[0].size, 4)
  assert_eq(elf.symbols[0].kind, "func")
  assert_eq(elf.symbols[0].bind, "global")
  assert_eq(elf.symbols[0].shndx, 1)
  assert_eq(elf.symbols[1].name, "helper")
  assert_eq(elf.symbols[1].value, 0x01001004)
  assert_eq(elf.symbols[1].kind, "object")
  assert_eq(elf.symbols[2].name, "printf")
  assert_eq(elf.symbols[2].shndx, -1)
  assert_eq(elf.symbols[3].name, "moonbin_version")
  assert_eq(elf.symbols[3].value, 0x01002000)
  assert_eq(elf.imports.length(), 1)
  assert_eq(elf.imports[0].library, "libc.so.6")
  assert_eq(elf.exports.length(), 1)
  assert_eq(elf.exports[0].name, "moonbin_version")
  assert_eq(elf.exports[0].rva, 0x01002000)
}

test "malformed and truncated inputs are refused" {
  let le = @core.Endian::Little
  let golden = build_elf(64, le)
  // Empty and short buffers.
  assert_true(@elf.parse(Bytes::makei(0, fn(_) { (0 : Int).to_byte() })) is Err(_))
  let cuts = [0, 1, 3, 4, 15, 16, 32, 63, 64, 100, 176, 300, 477, 600, 988]
  for cut in cuts {
    let prefix = Bytes::makei(cut, fn(i) { golden[i] })
    assert_true(@elf.parse(prefix) is Err(@core.ParseError::Truncated(_)))
  }
  // Bad magic.
  let bad_magic = patched_int(golden, 1, 0x58, 1, le)
  assert_true(@elf.parse(bad_magic) is Err(@core.ParseError::BadMagic(_)))
  // Invalid EI_CLASS / EI_DATA / EI_VERSION.
  assert_true(@elf.parse(patched_int(golden, 4, 3, 1, le)) is Err(@core.ParseError::Invalid(_)))
  assert_true(@elf.parse(patched_int(golden, 5, 3, 1, le)) is Err(@core.ParseError::Invalid(_)))
  assert_true(@elf.parse(patched_int(golden, 6, 0, 1, le)) is Err(@core.ParseError::Invalid(_)))
  // e_shoff pointing past end of file.
  assert_true(@elf.parse(patched_int(golden, 40, 0x7FFFFFFFFFFFFFFF, 8, le)) is Err(_))
  // .symtab sh_link out of range (section 2, sh_link at shoff + 2*64 + 40).
  let shoff = 477
  assert_true(@elf.parse(patched_int(golden, shoff + 2 * 64 + 40, 99, 4, le)) is Err(_))
  // Unterminated .strtab: overwrite the final NUL (strtab at 252, size 13).
  let unterminated = patched_int(golden, 252 + 12, 0x58, 1, le)
  assert_true(@elf.parse(unterminated) is Err(_))
  // e_ehsize wrong for the class.
  assert_true(@elf.parse(patched_int(golden, 52, 52, 2, le)) is Err(@core.ParseError::Invalid(_)))
}

test "elf without section headers still parses segments" {
  let le = @core.Endian::Little
  let golden = build_elf(64, le)
  let b = patched_int(golden, 40, 0, 8, le) // e_shoff = 0
  let b = patched_int(b, 58, 0, 2, le) // e_shentsize = 0
  let b = patched_int(b, 60, 0, 2, le) // e_shnum = 0
  let b = patched_int(b, 62, 0, 2, le) // e_shstrndx = 0
  let elf = @elf.parse(b).unwrap()
  assert_eq(elf.class, 64)
  assert_eq(elf.entry, 0x401000)
  assert_eq(elf.sections.length(), 0)
  assert_eq(elf.symbols.length(), 0)
  assert_eq(elf.imports.length(), 0)
  assert_eq(elf.exports.length(), 0)
  assert_eq(elf.segments.length(), 2)
  assert_eq(elf.segments[0].name, "LOAD")
  assert_eq(elf.segments[1].name, "DYNAMIC")
}

test "extended section and segment numbering (SHN_XINDEX / PN_XNUM)" {
  let le = @core.Endian::Little
  let golden = build_elf(64, le)
  let shoff = 64 + 2 * 56 + 4 + 3 * 24 + 13 + 3 * 24 + 34 + 3 * 16 + 58
  let b = patched_int(golden, 60, 0, 2, le) // e_shnum = 0 -> use shdr[0].sh_size
  let b = patched_int(b, 62, 0xFFFF, 2, le) // e_shstrndx = SHN_XINDEX -> shdr[0].sh_link
  let b = patched_int(b, 56, 0xFFFF, 2, le) // e_phnum = PN_XNUM -> shdr[0].sh_info
  let b = patched_int(b, shoff + 32, 8, 8, le) // shdr[0].sh_size = real shnum
  let b = patched_int(b, shoff + 40, 7, 4, le) // shdr[0].sh_link = real shstrndx
  let b = patched_int(b, shoff + 44, 2, 4, le) // shdr[0].sh_info = real phnum
  let elf = @elf.parse(b).unwrap()
  assert_eq(elf.sections.length(), 8)
  assert_eq(elf.sections[7].name, ".shstrtab")
  assert_eq(elf.segments.length(), 2)
  assert_eq(elf.symbols.length(), 4)
  assert_eq(elf.symbols[0].name, "main")
  assert_eq(elf.imports.length(), 1)
  assert_eq(elf.exports.length(), 1)
}

test "crosscheck dump crafted fixtures" {
  let b64 = build_elf(64, @core.Endian::Little)
  let b32 = build_elf(32, @core.Endian::Big)
  assert_eq(b64[0].to_int(), 0x7F)
  assert_eq(b32[0].to_int(), 0x7F)
  assert_eq(b64.length(), 989)
  assert_eq(b32.length(), 665)
  // Consumed by test/elf_crosscheck.sh, which decodes these lines and runs
  // GNU readelf on the exact bytes the golden tests assert on.
  println("ELFCROSS elf64le " + to_hex(b64))
  println("ELFCROSS elf32be " + to_hex(b32))
}