// Deterministic in-test Mach-O fixtures + golden assertions.
//
// build_macho(class, endian) crafts a complete, valid Mach-O with:
//   header (mach_header / mach_header_64)
//   1 segment "__TEXT" containing 1 section "__text" (4 bytes of code)
//   LC_SYMTAB: 2 nlist symbols "_main" (defined) + "_printf" (undefined)
//   LC_LOAD_DYLIB "/usr/lib/libSystem.B.dylib"
//   entry: LC_MAIN (64-bit, x86-64) or LC_UNIXTHREAD PPC_THREAD_STATE (32-bit)
// The exact same bytes are dumped as hex by the "crosscheck dump" test and
// verified against LIEF by test/macho_crosscheck.py.

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
fn put_name16(buf : Array[Byte], s : String) -> Unit {
  let mut n = 0
  for c in s {
    if n >= 16 {
      break
    }
    buf.push(c.to_int().to_byte())
    n = n + 1
  }
  while n < 16 {
    buf.push((0 : Int).to_byte())
    n = n + 1
  }
}

///|
fn put_nlist(
  buf : Array[Byte],
  class : Int,
  endian : @core.Endian,
  strx : Int64,
  ntype : Int64,
  nsect : Int64,
  ndesc : Int64,
  value : Int64
) -> Unit {
  put_int(buf, strx, 4, endian)
  put_int(buf, ntype, 1, endian)
  put_int(buf, nsect, 1, endian)
  put_int(buf, ndesc, 2, endian)
  put_int(buf, value, if class == 64 { 8 } else { 4 }, endian)
}

///|
fn build_macho(class : Int, endian : @core.Endian) -> Bytes {
  let aw = if class == 64 { 8 } else { 4 }
  let hdr_size = if class == 64 { 32 } else { 28 }
  let seg_hdr = if class == 64 { 72 } else { 56 }
  let sec_size = if class == 64 { 80 } else { 68 }
  let seg_cmdsize = seg_hdr + sec_size // one section
  let nlist_es = if class == 64 { 16 } else { 12 }
  let dylib_name = "/usr/lib/libSystem.B.dylib"
  let dylib_cmdsize = (24 + dylib_name.length() + 1 + 7) / 8 * 8
  let entry_cmdsize = if class == 64 { 24 } else { 16 + 40 * 4 }
  let sizeofcmds = seg_cmdsize + 24 + dylib_cmdsize + entry_cmdsize
  let text_off = hdr_size + sizeofcmds
  let symtab_off = text_off + 4
  let strtab_off = symtab_off + 2 * nlist_es
  let strtab_size = 15 // "\0_main\0_printf\0"
  let total = strtab_off + strtab_size
  let base : Int64 = if class == 64 { 0x100000000 } else { 0x1000 }
  let text_addr = base + text_off.to_int64()
  let cputype : Int64 = if class == 64 { 0x01000007 } else { 18 }
  let cpusubtype : Int64 = if class == 64 { 3 } else { 0 }
  let buf : Array[Byte] = []
  // Header, patched at the end.
  put_zeros(buf, hdr_size)
  // LC_SEGMENT / LC_SEGMENT_64 with one section.
  put_int(buf, if class == 64 { 0x19 } else { 0x1 }, 4, endian)
  put_int(buf, seg_cmdsize.to_int64(), 4, endian)
  put_name16(buf, "__TEXT")
  put_int(buf, base, aw, endian) // vmaddr
  put_int(buf, 0x1000, aw, endian) // vmsize
  put_int(buf, 0, aw, endian) // fileoff
  put_int(buf, total.to_int64(), aw, endian) // filesize
  put_int(buf, 7, 4, endian) // maxprot rwx
  put_int(buf, 5, 4, endian) // initprot rx
  put_int(buf, 1, 4, endian) // nsects
  put_int(buf, 0, 4, endian) // flags
  put_name16(buf, "__text")
  put_name16(buf, "__TEXT")
  put_int(buf, text_addr, aw, endian) // addr
  put_int(buf, 4, aw, endian) // size
  put_int(buf, text_off.to_int64(), 4, endian) // offset
  put_int(buf, 0, 4, endian) // align
  put_int(buf, 0, 4, endian) // reloff
  put_int(buf, 0, 4, endian) // nreloc
  put_int(buf, 0x80000400, 4, endian) // flags: pure+some instructions
  put_int(buf, 0, 4, endian) // reserved1
  put_int(buf, 0, 4, endian) // reserved2
  if class == 64 {
    put_int(buf, 0, 4, endian) // reserved3
  }
  // LC_SYMTAB
  put_int(buf, 0x2, 4, endian)
  put_int(buf, 24, 4, endian)
  put_int(buf, symtab_off.to_int64(), 4, endian)
  put_int(buf, 2, 4, endian) // nsyms
  put_int(buf, strtab_off.to_int64(), 4, endian)
  put_int(buf, strtab_size.to_int64(), 4, endian)
  // LC_LOAD_DYLIB
  put_int(buf, 0xC, 4, endian)
  put_int(buf, dylib_cmdsize.to_int64(), 4, endian)
  put_int(buf, 24, 4, endian) // name offset
  put_int(buf, 0, 4, endian) // timestamp
  put_int(buf, 0, 4, endian) // current_version
  put_int(buf, 0, 4, endian) // compatibility_version
  put_str(buf, dylib_name)
  while buf.length() < hdr_size + seg_cmdsize + 24 + dylib_cmdsize {
    buf.push((0 : Int).to_byte())
  }
  // Entry command.
  if class == 64 {
    // LC_MAIN: entryoff (file offset) + stacksize.
    put_int(buf, 0x80000028, 4, endian)
    put_int(buf, 24, 4, endian)
    put_int(buf, text_off.to_int64(), 8, endian)
    put_int(buf, 0, 8, endian)
  } else {
    // LC_UNIXTHREAD, PPC_THREAD_STATE (flavor 1), srr0 = PC.
    put_int(buf, 0x5, 4, endian)
    put_int(buf, entry_cmdsize.to_int64(), 4, endian)
    put_int(buf, 1, 4, endian) // flavor
    put_int(buf, 40, 4, endian) // count
    for i = 0; i < 40; i = i + 1 {
      put_int(buf, if i == 0 { text_addr } else { 0 }, 4, endian)
    }
  }
  // __text: 4 bytes of code.
  if class == 64 {
    buf.push((0x55 : Int).to_byte())
    buf.push((0x48 : Int).to_byte())
    buf.push((0x89 : Int).to_byte())
    buf.push((0xE5 : Int).to_byte())
  } else {
    buf.push((0x7C : Int).to_byte())
    buf.push((0x08 : Int).to_byte())
    buf.push((0x02 : Int).to_byte())
    buf.push((0xA6 : Int).to_byte())
  }
  // Symbol table: "_main" defined (N_SECT|N_EXT), "_printf" undefined.
  put_nlist(buf, class, endian, 1, 0x0F, 1, 0, text_addr)
  put_nlist(buf, class, endian, 7, 0x01, 0, 0, 0)
  // String table.
  put_str(buf, "")
  put_str(buf, "_main")
  put_str(buf, "_printf")
  // Patch header.
  let magic : Int64 = if class == 64 { 0xFEEDFACF } else { 0xFEEDFACE }
  patch_int(buf, 0, magic, 4, endian)
  patch_int(buf, 4, cputype, 4, endian)
  patch_int(buf, 8, cpusubtype, 4, endian)
  patch_int(buf, 12, 2, 4, endian) // MH_EXECUTE
  patch_int(buf, 16, 4, 4, endian) // ncmds
  patch_int(buf, 20, sizeofcmds.to_int64(), 4, endian)
  patch_int(buf, 24, 0, 4, endian) // flags
  if class == 64 {
    patch_int(buf, 28, 0, 4, endian) // reserved
  }
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

// Build a minimal Mach-O carrying a single LC_UNIXTHREAD with the given
// thread-state words (each a u32). Used to exercise PC extraction per arch.
///|
fn build_thread(
  class : Int,
  endian : @core.Endian,
  cputype : Int64,
  flavor : Int64,
  words : Array[Int64]
) -> Bytes {
  let hdr_size = if class == 64 { 32 } else { 28 }
  let count = words.length()
  let cmdsize = 16 + count * 4
  let buf : Array[Byte] = []
  put_zeros(buf, hdr_size)
  put_int(buf, 0x5, 4, endian) // LC_UNIXTHREAD
  put_int(buf, cmdsize.to_int64(), 4, endian)
  put_int(buf, flavor, 4, endian)
  put_int(buf, count.to_int64(), 4, endian)
  for w in words {
    put_int(buf, w, 4, endian)
  }
  let magic : Int64 = if class == 64 { 0xFEEDFACF } else { 0xFEEDFACE }
  patch_int(buf, 0, magic, 4, endian)
  patch_int(buf, 4, cputype, 4, endian)
  patch_int(buf, 8, 0, 4, endian)
  patch_int(buf, 12, 2, 4, endian)
  patch_int(buf, 16, 1, 4, endian) // ncmds
  patch_int(buf, 20, cmdsize.to_int64(), 4, endian)
  patch_int(buf, 24, 0, 4, endian)
  if class == 64 {
    patch_int(buf, 28, 0, 4, endian)
  }
  Bytes::from_array(buf)
}

///|
fn words32(count : Int, idx : Int, pc : Int64) -> Array[Int64] {
  let w : Array[Int64] = []
  for i = 0; i < count; i = i + 1 {
    w.push(0)
  }
  w[idx] = pc
  w
}

///|
fn words64(
  count : Int,
  idx : Int,
  pc : Int64,
  endian : @core.Endian
) -> Array[Int64] {
  let w : Array[Int64] = []
  for i = 0; i < count; i = i + 1 {
    w.push(0)
  }
  let lo = pc & 0xFFFFFFFF
  let hi = (pc >> 32) & 0xFFFFFFFF
  match endian {
    @core.Endian::Little => {
      w[idx] = lo
      w[idx + 1] = hi
    }
    @core.Endian::Big => {
      w[idx] = hi
      w[idx + 1] = lo
    }
  }
  w
}

test "macho64 little-endian golden parse" {
  let bytes = build_macho(64, @core.Endian::Little)
  let m = @macho.parse(bytes).unwrap()
  assert_eq(m.class, 64)
  assert_eq(m.endian, @core.Endian::Little)
  assert_eq(m.cpu, 0x01000007)
  assert_eq(m.entry, 0x100000120)
  // One segment __TEXT covering the whole file.
  assert_eq(m.segments.length(), 1)
  assert_eq(m.segments[0].name, "__TEXT")
  assert_eq(m.segments[0].offset, 0)
  assert_eq(m.segments[0].size, 339)
  assert_eq(m.segments[0].vaddr, 0x100000000)
  assert_eq(m.segments[0].flags, "rx")
  // One section __text.
  assert_eq(m.sections.length(), 1)
  assert_eq(m.sections[0].name, "__text")
  assert_eq(m.sections[0].offset, 288)
  assert_eq(m.sections[0].size, 4)
  assert_eq(m.sections[0].vaddr, 0x100000120)
  assert_eq(m.sections[0].flags, "rx")
  // Two symbols: defined _main, undefined _printf.
  assert_eq(m.symbols.length(), 2)
  assert_eq(m.symbols[0].name, "_main")
  assert_eq(m.symbols[0].value, 0x100000120)
  assert_eq(m.symbols[0].size, 0)
  assert_eq(m.symbols[0].kind, "section")
  assert_eq(m.symbols[0].bind, "global")
  assert_eq(m.symbols[0].shndx, 1)
  assert_eq(m.symbols[1].name, "_printf")
  assert_eq(m.symbols[1].value, 0)
  assert_eq(m.symbols[1].kind, "undefined")
  assert_eq(m.symbols[1].bind, "global")
  assert_eq(m.symbols[1].shndx, -1)
  // One dylib import; defined symbols are exports.
  assert_eq(m.imports.length(), 1)
  assert_eq(m.imports[0].library, "/usr/lib/libSystem.B.dylib")
  assert_eq(m.imports[0].name, "")
  assert_eq(m.exports.length(), 1)
  assert_eq(m.exports[0].name, "_main")
  assert_eq(m.exports[0].ordinal, 0)
  assert_eq(m.exports[0].rva, 0x100000120)
}

test "macho32 big-endian golden parse" {
  let bytes = build_macho(32, @core.Endian::Big)
  let m = @macho.parse(bytes).unwrap()
  assert_eq(m.class, 32)
  assert_eq(m.endian, @core.Endian::Big)
  assert_eq(m.cpu, 18)
  assert_eq(m.entry, 0x1198) // PPC srr0 via LC_UNIXTHREAD
  assert_eq(m.segments.length(), 1)
  assert_eq(m.segments[0].name, "__TEXT")
  assert_eq(m.segments[0].offset, 0)
  assert_eq(m.segments[0].size, 451)
  assert_eq(m.segments[0].vaddr, 0x1000)
  assert_eq(m.segments[0].flags, "rx")
  assert_eq(m.sections.length(), 1)
  assert_eq(m.sections[0].name, "__text")
  assert_eq(m.sections[0].offset, 408)
  assert_eq(m.sections[0].size, 4)
  assert_eq(m.sections[0].vaddr, 0x1198)
  assert_eq(m.sections[0].flags, "rx")
  assert_eq(m.symbols.length(), 2)
  assert_eq(m.symbols[0].name, "_main")
  assert_eq(m.symbols[0].value, 0x1198)
  assert_eq(m.symbols[0].kind, "section")
  assert_eq(m.symbols[0].bind, "global")
  assert_eq(m.symbols[0].shndx, 1)
  assert_eq(m.symbols[1].name, "_printf")
  assert_eq(m.symbols[1].value, 0)
  assert_eq(m.symbols[1].kind, "undefined")
  assert_eq(m.symbols[1].shndx, -1)
  assert_eq(m.imports.length(), 1)
  assert_eq(m.imports[0].library, "/usr/lib/libSystem.B.dylib")
  assert_eq(m.exports.length(), 1)
  assert_eq(m.exports[0].name, "_main")
  assert_eq(m.exports[0].rva, 0x1198)
}

test "macho64 big-endian and macho32 little-endian parse" {
  let m64 = @macho.parse(build_macho(64, @core.Endian::Big)).unwrap()
  assert_eq(m64.class, 64)
  assert_eq(m64.endian, @core.Endian::Big)
  assert_eq(m64.cpu, 0x01000007)
  assert_eq(m64.entry, 0x100000120)
  assert_eq(m64.sections[0].name, "__text")
  assert_eq(m64.symbols[0].name, "_main")
  assert_eq(m64.imports[0].library, "/usr/lib/libSystem.B.dylib")
  let m32 = @macho.parse(build_macho(32, @core.Endian::Little)).unwrap()
  assert_eq(m32.class, 32)
  assert_eq(m32.endian, @core.Endian::Little)
  assert_eq(m32.cpu, 18)
  assert_eq(m32.entry, 0x1198)
  assert_eq(m32.sections[0].name, "__text")
  assert_eq(m32.symbols[0].name, "_main")
  assert_eq(m32.exports[0].rva, 0x1198)
}

test "LC_LOAD_WEAK_DYLIB is an import" {
  let le = @core.Endian::Little
  let golden = build_macho(64, le)
  // LC_LOAD_DYLIB cmd field sits at offset 32 + 152 + 24 = 208.
  let b = patched_int(golden, 208, 0x18, 4, le) // LC_LOAD_WEAK_DYLIB
  let m = @macho.parse(b).unwrap()
  assert_eq(m.imports.length(), 1)
  assert_eq(m.imports[0].library, "/usr/lib/libSystem.B.dylib")
}

test "symbol binding: weak, private, local" {
  let le = @core.Endian::Little
  let golden = build_macho(64, le)
  // _main nlist starts at symtab_off = 292: n_strx(4) n_type(1) n_sect(1)
  // n_desc(2) n_value(8). n_type at 296, n_desc at 298.
  // N_EXT|N_PEXT (0x11) -> private.
  let prv = patched_int(golden, 296, 0x1F, 1, le) // N_SECT|N_EXT|N_PEXT
  assert_eq(@macho.parse(prv).unwrap().symbols[0].bind, "private")
  // N_EXT + N_WEAK_DEF (0x0080 in n_desc) -> weak.
  let weak = patched_int(golden, 298, 0x0080, 2, le)
  assert_eq(@macho.parse(weak).unwrap().symbols[0].bind, "weak")
  // Clear N_EXT -> local.
  let loc = patched_int(golden, 296, 0x0E, 1, le) // N_SECT only
  let ml = @macho.parse(loc).unwrap()
  assert_eq(ml.symbols[0].bind, "local")
  // A local defined symbol is still an export (defined, non-stab).
  assert_eq(ml.exports.length(), 1)
}

test "LC_UNIXTHREAD entry extraction across architectures" {
  let le = @core.Endian::Little
  let be = @core.Endian::Big
  // x86-64, x86_THREAD_STATE64 (flavor 4): rip at u64 index 16.
  let x64 = build_thread(64, le, 0x01000007, 4, words64(42, 32, 0x100000ABC, le))
  assert_eq(@macho.parse(x64).unwrap().entry, 0x100000ABC)
  // x86, x86_THREAD_STATE32 (flavor 1): eip at u32 index 10.
  let x86 = build_thread(32, le, 7, 1, words32(16, 10, 0x8048000))
  assert_eq(@macho.parse(x86).unwrap().entry, 0x8048000)
  // ARM, ARM_THREAD_STATE (flavor 1): pc at u32 index 15.
  let arm = build_thread(32, le, 12, 1, words32(17, 15, 0x8000))
  assert_eq(@macho.parse(arm).unwrap().entry, 0x8000)
  // ARM64, ARM_THREAD_STATE64 (flavor 6): pc at u64 index 32.
  let arm64 = build_thread(64, le, 0x0100000C, 6, words64(70, 64, 0x100004000, le))
  assert_eq(@macho.parse(arm64).unwrap().entry, 0x100004000)
  // PPC, PPC_THREAD_STATE (flavor 1): srr0 at u32 index 0 (big-endian).
  let ppc = build_thread(32, be, 18, 1, words32(40, 0, 0x1198))
  assert_eq(@macho.parse(ppc).unwrap().entry, 0x1198)
  // PPC64, PPC_THREAD_STATE64 (flavor 5): srr0 at u64 index 0.
  let ppc64 = build_thread(64, be, 0x01000012, 5, words64(44, 0, 0x100001234, be))
  assert_eq(@macho.parse(ppc64).unwrap().entry, 0x100001234)
  // Unsupported flavor for the cputype -> Invalid, never guess.
  let bad_flavor = build_thread(64, le, 0x01000007, 99, words64(42, 32, 0x1000, le))
  assert_true(@macho.parse(bad_flavor) is Err(@core.ParseError::Invalid(_)))
  // State too short to hold the PC field -> Invalid.
  let short = build_thread(64, le, 0x01000007, 4, words64(20, 0, 0x1000, le))
  assert_true(@macho.parse(short) is Err(@core.ParseError::Invalid(_)))
}

test "malformed and truncated inputs are refused" {
  let le = @core.Endian::Little
  let golden = build_macho(64, le)
  // Empty and short buffers.
  assert_true(@macho.parse(Bytes::makei(0, fn(_) { (0 : Int).to_byte() })) is Err(_))
  let cuts = [0, 1, 3, 4, 27, 28, 31, 32, 100, 184, 208, 264, 288, 292, 324, 338]
  for cut in cuts {
    let prefix = Bytes::makei(cut, fn(i) { golden[i] })
    assert_true(@macho.parse(prefix) is Err(@core.ParseError::Truncated(_)))
  }
  // Bad magic.
  let bad_magic = patched_int(golden, 0, 0x12345678, 4, le)
  assert_true(@macho.parse(bad_magic) is Err(@core.ParseError::BadMagic(_)))
  // sizeofcmds past end of file (header field at offset 20).
  assert_true(@macho.parse(patched_int(golden, 20, 0x7FFFFFFF, 4, le)) is Err(_))
  // ncmds larger than the command area can hold.
  assert_true(@macho.parse(patched_int(golden, 16, 0x7FFFFFFF, 4, le)) is Err(_))
  // First load command cmdsize < 8 (at offset 32 + 4 = 36).
  assert_true(@macho.parse(patched_int(golden, 36, 4, 4, le)) is Err(@core.ParseError::Invalid(_)))
  // Segment nsects huge: 64-bit segment starts at 32, nsects is at +64 = 96.
  // More sections than the command size can hold -> Invalid.
  assert_true(@macho.parse(patched_int(golden, 96, 0x7FFFFFFF, 4, le)) is Err(@core.ParseError::Invalid(_)))
  // Segment filesize past EOF (filesize at segment +48 = 80) -> Truncated.
  assert_true(@macho.parse(patched_int(golden, 80, 0x7FFFFFFF, 8, le)) is Err(@core.ParseError::Truncated(_)))
  // Section offset past EOF (section starts at 104, offset field at +48 = 152).
  assert_true(@macho.parse(patched_int(golden, 152, 0x7FFFFFFF, 4, le)) is Err(@core.ParseError::Truncated(_)))
  // LC_SYMTAB symoff past EOF (symtab cmd at 184, symoff at 184 + 8 = 192).
  assert_true(@macho.parse(patched_int(golden, 192, 0x7FFFFFFF, 4, le)) is Err(_))
  // Unterminated symbol string: overwrite final NUL of strtab (324 + 14).
  let unterminated = patched_int(golden, 324 + 14, 0x58, 1, le)
  assert_true(@macho.parse(unterminated) is Err(_))
  // Symbol string offset outside the string table (_main n_strx at 292).
  assert_true(@macho.parse(patched_int(golden, 292, 999, 4, le)) is Err(@core.ParseError::Invalid(_)))
  // LC_MAIN entryoff past EOF (entryoff at 264 + 8 = 272).
  assert_true(@macho.parse(patched_int(golden, 272, 0x7FFFFFFF, 8, le)) is Err(@core.ParseError::Invalid(_)))
}

test "crosscheck dump crafted fixtures" {
  let b64 = build_macho(64, @core.Endian::Little)
  let b32 = build_macho(32, @core.Endian::Big)
  assert_eq(b64.length(), 339)
  assert_eq(b32.length(), 451)
  // Consumed by test/macho_crosscheck.py, which decodes these lines and runs
  // LIEF on the exact bytes the golden tests assert on.
  println("MACHOCROSS macho64le " + to_hex(b64))
  println("MACHOCROSS macho32be " + to_hex(b32))
}