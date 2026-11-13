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
  (if v < 10 { 48 + v } else { 87 + v }).unsafe_to_char()
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

// ---------------------------------------------------------------------------
// Relocation fixture: build_elf plus
//   [8] .rela.plt  SHT_RELA, link -> .dynsym(4), info -> .got.plt(10)
//       R_X86_64_JUMP_SLOT (7) -> dynsym 1 "printf"   @ base+0x5000
//       R_X86_64_GLOB_DAT  (6) -> dynsym 2 "moonbin_version" @ base+0x5008
//       R_X86_64_RELATIVE  (8) -> no symbol, addend 0x1234 (must be skipped)
//   [9] .rel.dyn   SHT_REL (9), link -> .dynsym(4), info -> .got(11)
//       JMP_SLOT (7) -> dynsym 1 "printf"   @ base+0x5100
//       GLOB_DAT (6) -> dynsym 2 "moonbin_version" @ base+0x5104
//       (ELF64: R_X86_64_* with 32-bit symbol shift; ELF32: R_386_* with 8)
//   [10] .got.plt  PROGBITS, [11] .got PROGBITS (targets, zero-filled)
//   .dynamic gains DT_JMPREL(23) -> .rela.plt, DT_PLTRELSZ(2), DT_PLTREL(20)=7
// The same bytes are dumped as "ELFCROSS rela64le" / "ELFCROSS rel32be" and
// verified against `readelf -r` by test/elf_crosscheck.sh.
// ---------------------------------------------------------------------------

///|
fn put_rela(
  buf : Array[Byte],
  class : Int,
  endian : @core.Endian,
  off : Int64,
  info : Int64,
  addend : Int64
) -> Unit {
  let aw = if class == 64 { 8 } else { 4 }
  put_int(buf, off, aw, endian)
  put_int(buf, info, aw, endian)
  put_int(buf, addend, aw, endian)
}

///|
fn put_rel(
  buf : Array[Byte],
  class : Int,
  endian : @core.Endian,
  off : Int64,
  info : Int64
) -> Unit {
  let aw = if class == 64 { 8 } else { 4 }
  put_int(buf, off, aw, endian)
  put_int(buf, info, aw, endian)
}

///|
fn build_elf_reloc(class : Int, endian : @core.Endian) -> Bytes {
  let aw = if class == 64 { 8 } else { 4 }
  let ehsize = if class == 64 { 64 } else { 52 }
  let phentsize = if class == 64 { 56 } else { 32 }
  let shentsize = if class == 64 { 64 } else { 40 }
  let sym_es = if class == 64 { 24 } else { 16 }
  let dyn_es = if class == 64 { 16 } else { 8 }
  let rela_es = if class == 64 { 24 } else { 12 }
  let rel_es = if class == 64 { 16 } else { 8 }
  let machine = if class == 64 { 62 } else { 3 }
  let base : Int64 = if class == 64 { 0x400000 } else { 0x01000000 }
  let text_addr = base + 0x1000
  let buf : Array[Byte] = []
  put_zeros(buf, ehsize)
  let phoff = buf.length()
  put_zeros(buf, 2 * phentsize)
  // .text
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
  // .strtab
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
  // .dynstr
  let dynstr_off = buf.length()
  put_str(buf, "")
  put_str(buf, "printf")
  put_str(buf, "moonbin_version")
  put_str(buf, "libc.so.6")
  let dynstr_size = buf.length() - dynstr_off
  // .dynamic: DT_NEEDED, DT_STRTAB, DT_JMPREL, DT_PLTRELSZ, DT_PLTREL, DT_NULL
  let dyn_off = buf.length()
  put_int(buf, 1, dyn_es / 2, endian)
  put_int(buf, 24, dyn_es / 2, endian)
  put_int(buf, 5, dyn_es / 2, endian)
  put_int(buf, base + 0x3000, dyn_es / 2, endian)
  let jmprel_pos = buf.length()
  put_int(buf, 23, dyn_es / 2, endian)
  put_int(buf, 0, dyn_es / 2, endian) // DT_JMPREL value patched below
  put_int(buf, 2, dyn_es / 2, endian)
  put_int(buf, (3 * rela_es).to_int64(), dyn_es / 2, endian)
  put_int(buf, 20, dyn_es / 2, endian)
  put_int(buf, 7, dyn_es / 2, endian) // DT_PLTREL = DT_RELA
  put_int(buf, 0, dyn_es / 2, endian)
  put_int(buf, 0, dyn_es / 2, endian)
  // r_info symbol shift is 32 for ELF64, 8 for ELF32.
  let info_shift = if class == 64 { 32 } else { 8 }
  // .rela.plt: JUMP_SLOT printf, GLOB_DAT moonbin_version, RELATIVE (no sym)
  let rela_off = buf.length()
  put_rela(buf, class, endian, base + 0x5000, (1 << info_shift) | 7, 0)
  put_rela(buf, class, endian, base + 0x5008, (2 << info_shift) | 6, 0)
  put_rela(buf, class, endian, base + 0x5010, 8, 0x1234)
  // .rel.dyn (SHT_REL, implicit addend): JMP_SLOT printf, GLOB_DAT
  // moonbin_version.
  let rel_off = buf.length()
  put_rel(buf, class, endian, base + 0x5100, (1 << info_shift) | 7)
  put_rel(buf, class, endian, base + 0x5104, (2 << info_shift) | 6)
  // .got.plt and .got targets (zero-filled)
  let gotplt_off = buf.length()
  put_zeros(buf, 3 * aw)
  let got_off = buf.length()
  put_zeros(buf, 2 * aw)
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
  put_str(buf, ".rela.plt")
  put_str(buf, ".rel.dyn")
  put_str(buf, ".got.plt")
  put_str(buf, ".got")
  let shstrtab_size = buf.length() - shstrtab_off
  // Section header table: 12 sections.
  let shoff = buf.length()
  put_zeros(buf, shentsize) // [0] NULL
  put_shdr(buf, class, endian, 1, 1, 6, text_addr, text_off.to_int64(), 4, 0, 0, 16, 0)
  put_shdr(buf, class, endian, 7, 2, 0, 0, symtab_off.to_int64(), (3 * sym_es).to_int64(), 3, 1, 8, sym_es.to_int64())
  put_shdr(buf, class, endian, 15, 3, 0, 0, strtab_off.to_int64(), strtab_size.to_int64(), 0, 0, 1, 0)
  put_shdr(buf, class, endian, 23, 11, 2, base + 0x2000, dynsym_off.to_int64(), (3 * sym_es).to_int64(), 5, 1, 8, sym_es.to_int64())
  put_shdr(buf, class, endian, 31, 3, 2, base + 0x3000, dynstr_off.to_int64(), dynstr_size.to_int64(), 0, 0, 1, 0)
  put_shdr(buf, class, endian, 39, 6, 3, base + 0x4000, dyn_off.to_int64(), (6 * dyn_es).to_int64(), 5, 0, 8, dyn_es.to_int64())
  put_shdr(buf, class, endian, 48, 3, 0, 0, shstrtab_off.to_int64(), shstrtab_size.to_int64(), 0, 0, 1, 0)
  put_shdr(buf, class, endian, 58, 4, 0x42, base + 0x5000, rela_off.to_int64(), (3 * rela_es).to_int64(), 4, 10, 8, rela_es.to_int64())
  put_shdr(buf, class, endian, 68, 9, 0x42, base + 0x5100, rel_off.to_int64(), (2 * rel_es).to_int64(), 4, 11, 8, rel_es.to_int64())
  put_shdr(buf, class, endian, 77, 1, 3, base + 0x5000, gotplt_off.to_int64(), (3 * aw).to_int64(), 0, 0, 8, 0)
  put_shdr(buf, class, endian, 86, 1, 3, base + 0x5100, got_off.to_int64(), (2 * aw).to_int64(), 0, 0, 8, 0)
  let total = buf.length().to_int64()
  // DT_JMPREL points at .rela.plt's mapped address.
  patch_int(buf, jmprel_pos + dyn_es / 2, base + 0x5000, dyn_es / 2, endian)
  patch_phdr(buf, phoff, class, endian, 1, 5, 0, base, total, 0x1000)
  patch_phdr(buf, phoff + phentsize, class, endian, 2, 6, dyn_off.to_int64(), base + 0x4000, (6 * dyn_es).to_int64(), 8)
  // ELF header.
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
  buf[6] = (1 : Int).to_byte()
  patch_int(buf, 16, 2, 2, endian) // e_type = ET_EXEC
  patch_int(buf, 18, machine.to_int64(), 2, endian)
  patch_int(buf, 20, 1, 4, endian)
  patch_int(buf, 24, text_addr, aw, endian)
  patch_int(buf, 24 + aw, phoff.to_int64(), aw, endian)
  patch_int(buf, 24 + 2 * aw, shoff.to_int64(), aw, endian)
  patch_int(buf, 24 + 3 * aw, 0, 4, endian)
  patch_int(buf, 28 + 3 * aw, ehsize.to_int64(), 2, endian)
  patch_int(buf, 30 + 3 * aw, phentsize.to_int64(), 2, endian)
  patch_int(buf, 32 + 3 * aw, 2, 2, endian)
  patch_int(buf, 34 + 3 * aw, shentsize.to_int64(), 2, endian)
  patch_int(buf, 36 + 3 * aw, 12, 2, endian) // e_shnum
  patch_int(buf, 38 + 3 * aw, 7, 2, endian) // e_shstrndx
  Bytes::from_array(buf)
}

test "elf64 rela.plt and rel.dyn import attribution" {
  let elf = @elf.parse(build_elf_reloc(64, @core.Endian::Little)).unwrap()
  assert_eq(elf.sections.length(), 12)
  assert_eq(elf.sections[8].name, ".rela.plt")
  assert_eq(elf.sections[9].name, ".rel.dyn")
  assert_eq(elf.sections[10].name, ".got.plt")
  assert_eq(elf.sections[11].name, ".got")
  // JUMP_SLOT/GLOB_DAT from both tables; RELATIVE has no symbol.
  assert_eq(elf.reloc_imports.length(), 4)
  assert_eq(elf.reloc_imports[0].library, "libc.so.6")
  assert_eq(elf.reloc_imports[0].name, "printf")
  assert_eq(elf.reloc_imports[1].library, "libc.so.6")
  assert_eq(elf.reloc_imports[1].name, "moonbin_version")
  assert_eq(elf.reloc_imports[2].library, "libc.so.6")
  assert_eq(elf.reloc_imports[2].name, "printf")
  assert_eq(elf.reloc_imports[3].library, "libc.so.6")
  assert_eq(elf.reloc_imports[3].name, "moonbin_version")
  // Per-DT_NEEDED imports and everything else stay unchanged.
  assert_eq(elf.imports.length(), 1)
  assert_eq(elf.imports[0].library, "libc.so.6")
  assert_eq(elf.imports[0].name, "")
  assert_eq(elf.symbols.length(), 4)
  assert_eq(elf.exports.length(), 1)
  assert_eq(elf.exports[0].name, "moonbin_version")
}

test "elf32 rel import attribution (big endian)" {
  let elf = @elf.parse(build_elf_reloc(32, @core.Endian::Big)).unwrap()
  assert_eq(elf.sections.length(), 12)
  assert_eq(elf.reloc_imports.length(), 4)
  assert_eq(elf.reloc_imports[0].library, "libc.so.6")
  assert_eq(elf.reloc_imports[0].name, "printf")
  assert_eq(elf.reloc_imports[1].name, "moonbin_version")
  assert_eq(elf.reloc_imports[2].name, "printf")
  assert_eq(elf.reloc_imports[3].name, "moonbin_version")
  assert_eq(elf.imports.length(), 1)
  assert_eq(elf.imports[0].library, "libc.so.6")
}

///|
fn read_u64le(b : Bytes, at : Int) -> Int64 {
  let mut v : Int64 = 0
  for i = 0; i < 8; i = i + 1 {
    v = v | (b[at + i].to_int().to_int64() << (i * 8))
  }
  v
}

test "relocation symbol index out of range refused" {
  let le = @core.Endian::Little
  let b = build_elf_reloc(64, le)
  let shoff = read_u64le(b, 40).to_int() // e_shoff
  // section 8 (.rela.plt) sh_offset field at shoff + 8*64 + 24
  let rela_off = read_u64le(b, shoff + 8 * 64 + 24)
  // r_info of entry 0 at rela_off + 8; symbol index 99 -> out of range.
  let bad = patched_int(b, rela_off.to_int() + 8, (99 << 32) | 7, 8, le)
  assert_true(@elf.parse(bad) is Err(@core.ParseError::Invalid(_)))
}

test "relocation table with bad sh_link refused" {
  let le = @core.Endian::Little
  let b = build_elf_reloc(64, le)
  let shoff = read_u64le(b, 40).to_int()
  // section 8 sh_link at shoff + 8*64 + 40 -> 99 (out of range)
  let bad = patched_int(b, shoff + 8 * 64 + 40, 99, 4, le)
  assert_true(@elf.parse(bad) is Err(_))
}

test "relocation entry size mismatch refused" {
  let le = @core.Endian::Little
  let b = build_elf_reloc(64, le)
  let shoff = read_u64le(b, 40).to_int()
  // section 8 sh_entsize at shoff + 8*64 + 56 -> 8 (not 24)
  let bad = patched_int(b, shoff + 8 * 64 + 56, 8, 8, le)
  assert_true(@elf.parse(bad) is Err(@core.ParseError::Invalid(_)))
}

test "base elf fixture has empty reloc_imports" {
  let elf = @elf.parse(build_elf(64, @core.Endian::Little)).unwrap()
  assert_eq(elf.reloc_imports.length(), 0)
  let elf32 = @elf.parse(build_elf(32, @core.Endian::Big)).unwrap()
  assert_eq(elf32.reloc_imports.length(), 0)
}

test "crosscheck dump reloc fixtures" {
  let r64 = build_elf_reloc(64, @core.Endian::Little)
  let r32 = build_elf_reloc(32, @core.Endian::Big)
  assert_eq(r64[0].to_int(), 0x7F)
  assert_eq(r32[0].to_int(), 0x7F)
  // Consumed by test/elf_crosscheck.sh (readelf -r).
  println("ELFCROSS rela64le " + to_hex(r64))
  println("ELFCROSS rel32be " + to_hex(r32))
}