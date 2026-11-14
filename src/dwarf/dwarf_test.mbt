// Hand-written unit tests: crafted minimal DWARF v4 and v5 line programs and
// .debug_info units, asserting exact (addr, file, line) / (name, low, high).
// The objdump cross-check on a real fixture lives in crosscheck_test.mbt.

// ---------------------------------------------------------------------------
// Byte builders (little-endian, as produced by x86 toolchains).

fn push_u16(a : Array[Byte], v : Int) -> Unit {
  a.push((v & 0xFF).to_byte())
  a.push(((v >> 8) & 0xFF).to_byte())
}

fn push_u32(a : Array[Byte], v : Int) -> Unit {
  for i = 0; i < 4; i = i + 1 {
    a.push(((v >> (i * 8)) & 0xFF).to_byte())
  }
}

fn push_u64(a : Array[Byte], v : Int64) -> Unit {
  for i = 0; i < 8; i = i + 1 {
    a.push(((v >> (i * 8)) & 0xFFL).to_int().to_byte())
  }
}

fn push_uleb(a : Array[Byte], v : Int) -> Unit {
  let mut x = v
  while true {
    let b = x & 0x7F
    x = x >> 7
    if x == 0 {
      a.push(b.to_byte())
      break
    }
    a.push((b | 0x80).to_byte())
  }
}

fn push_sleb(a : Array[Byte], v : Int) -> Unit {
  let mut x = v
  while true {
    let b = x & 0x7F
    x = x >> 7
    if (x == 0 && (b & 0x40) == 0) || (x == -1 && (b & 0x40) != 0) {
      a.push(b.to_byte())
      break
    }
    a.push((b | 0x80).to_byte())
  }
}

fn push_cstr(a : Array[Byte], s : String) -> Unit {
  for i = 0; i < s.length(); i = i + 1 {
    a.push(s[i].to_int().to_byte())
  }
  a.push((0).to_byte())
}

fn append(a : Array[Byte], b : Array[Byte]) -> Unit {
  for i = 0; i < b.length(); i = i + 1 {
    a.push(b[i])
  }
}

fn prefix(data : Bytes, n : Int) -> Bytes {
  Bytes::makei(n, fn(i) { data[i] })
}

// ---------------------------------------------------------------------------
// Line program builders.

// min_inst=1, max_ops=1, is_stmt=1, then line_base/line_range/opcode_base and
// the standard opcode lengths for DW_LNS 1..12.
fn std_prologue(line_base : Int, line_range : Int, opcode_base : Int) -> Array[Byte] {
  let p : Array[Byte] = []
  p.push((1).to_byte()) // minimum_instruction_length
  p.push((1).to_byte()) // maximum_operations_per_instruction
  p.push((1).to_byte()) // default_is_stmt
  p.push((line_base & 0xFF).to_byte())
  p.push(line_range.to_byte())
  p.push(opcode_base.to_byte())
  let lens = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]
  for i = 0; i < opcode_base - 1; i = i + 1 {
    p.push(lens[i].to_byte())
  }
  p
}

fn v4_tables(p : Array[Byte], dirs : Array[String], files : Array[(String, Int)]) -> Unit {
  for i = 0; i < dirs.length(); i = i + 1 {
    push_cstr(p, dirs[i])
  }
  p.push((0).to_byte())
  for i = 0; i < files.length(); i = i + 1 {
    let (name, dir) = files[i]
    push_cstr(p, name)
    push_uleb(p, dir)
    push_uleb(p, 0) // mtime
    push_uleb(p, 0) // size
  }
  p.push((0).to_byte())
}

// Wrap prologue+program into a v4 line unit with correct lengths.
fn line_unit_v4(prologue : Array[Byte], program : Array[Byte]) -> Bytes {
  let body : Array[Byte] = []
  push_u16(body, 4)
  push_u32(body, prologue.length()) // header_length
  append(body, prologue)
  append(body, program)
  let out : Array[Byte] = []
  push_u32(out, body.length()) // unit_length
  append(out, body)
  Bytes::from_array(out)
}

// v5 adds address_size + segment_selector_size between version and
// header_length; those two bytes are NOT counted by header_length.
fn ext_set_address(p : Array[Byte], addr : Int64) -> Unit {
  p.push((0).to_byte())
  push_uleb(p, 9) // 1 subopcode byte + 8 address bytes
  p.push((2).to_byte())
  push_u64(p, addr)
}

fn ext_end_sequence(p : Array[Byte]) -> Unit {
  p.push((0).to_byte())
  push_uleb(p, 1)
  p.push((1).to_byte())
}

fn advance_pc(p : Array[Byte], n : Int) -> Unit {
  p.push((2).to_byte())
  push_uleb(p, n)
}

fn advance_line(p : Array[Byte], n : Int) -> Unit {
  p.push((3).to_byte())
  push_sleb(p, n)
}

fn set_file(p : Array[Byte], n : Int) -> Unit {
  p.push((4).to_byte())
  push_uleb(p, n)
}

fn copy(p : Array[Byte]) -> Unit {
  p.push((1).to_byte())
}

// ---------------------------------------------------------------------------
// .debug_info builders.

fn push_abbrev(
  a : Array[Byte],
  code : Int,
  tag : Int,
  has_children : Bool,
  attrs : Array[(Int, Int)]
) -> Unit {
  push_uleb(a, code)
  push_uleb(a, tag)
  a.push((if has_children { 1 } else { 0 }).to_byte())
  for i = 0; i < attrs.length(); i = i + 1 {
    let (at, fm) = attrs[i]
    push_uleb(a, at)
    push_uleb(a, fm)
  }
  push_uleb(a, 0)
  push_uleb(a, 0)
}

fn cu_v4(abbrev_offset : Int, address_size : Int, dies : Array[Byte]) -> Bytes {
  let body : Array[Byte] = []
  push_u16(body, 4)
  push_u32(body, abbrev_offset)
  body.push(address_size.to_byte())
  append(body, dies)
  let out : Array[Byte] = []
  push_u32(out, body.length())
  append(out, body)
  Bytes::from_array(out)
}

fn make_regions(names : Array[String], blobs : Array[Bytes]) -> (Bytes, Array[@core.Region]) {
  let arr : Array[Byte] = []
  let regions : Array[@core.Region] = []
  let mut off = 0
  for i = 0; i < blobs.length(); i = i + 1 {
    regions.push({
      name: names[i],
      offset: off.to_int64(),
      size: blobs[i].length().to_int64(),
      vaddr: 0L,
      flags: "",
    })
    for j = 0; j < blobs[i].length(); j = j + 1 {
      arr.push(blobs[i][j])
    }
    off = off + blobs[i].length()
  }
  (Bytes::from_array(arr), regions)
}

fn one_region(name : String, data : Bytes) -> (Bytes, Array[@core.Region]) {
  make_regions([name], [data])
}

fn check_lines(
  data : Bytes,
  regions : Array[@core.Region],
  expected : Array[(Int64, String, Int)]
) -> Unit raise {
  match @dwarf.decode_lines(data, regions) {
    Ok(rows) => {
      assert_eq(rows.length(), expected.length())
      for i = 0; i < expected.length(); i = i + 1 {
        let (addr, file, line) = expected[i]
        assert_eq(rows[i].addr, addr)
        assert_eq(rows[i].file, file)
        assert_eq(rows[i].line, line)
      }
    }
    Err(e) => {
      inspect(e, content="expected Ok line rows, got refusal:")
      assert_true(false)
    }
  }
}

fn check_funcs(
  data : Bytes,
  regions : Array[@core.Region],
  expected : Array[(String, Int64, Int64)]
) -> Unit raise {
  match @dwarf.decode_funcs(data, regions) {
    Ok(funcs) => {
      assert_eq(funcs.length(), expected.length())
      for i = 0; i < expected.length(); i = i + 1 {
        let (name, low, high) = expected[i]
        assert_eq(funcs[i].name, name)
        assert_eq(funcs[i].low, low)
        assert_eq(funcs[i].high, high)
      }
    }
    Err(e) => {
      inspect(e, content="expected Ok funcs, got refusal:")
      assert_true(false)
    }
  }
}

fn expect_lines_truncated(data : Bytes, regions : Array[@core.Region]) -> Unit raise {
  match @dwarf.decode_lines(data, regions) {
    Err(@core.ParseError::Truncated(_)) => ()
    Ok(rows) => {
      inspect(rows.length(), content="expected Truncated, decoded rows:")
      assert_true(false)
    }
    Err(e) => {
      inspect(e, content="expected Truncated, got:")
      assert_true(false)
    }
  }
}

fn expect_lines_invalid(data : Bytes, regions : Array[@core.Region]) -> Unit raise {
  match @dwarf.decode_lines(data, regions) {
    Err(@core.ParseError::Invalid(_)) => ()
    Ok(rows) => {
      inspect(rows.length(), content="expected Invalid, decoded rows:")
      assert_true(false)
    }
    Err(e) => {
      inspect(e, content="expected Invalid, got:")
      assert_true(false)
    }
  }
}

test "line v4: copy, special, set_file, advance_pc/line, fixed and const add_pc" {
  let prologue = std_prologue(-5, 14, 13)
  v4_tables(prologue, ["src", "inc"], [("a.c", 1), ("b.c", 2)])
  let p : Array[Byte] = []
  ext_set_address(p, 0x1000L)
  advance_line(p, 9) // line 1 -> 10
  copy(p) // (0x1000, a.c, 10)
  p.push((44).to_byte()) // special: adjusted 31 -> addr +2, line -2
  set_file(p, 2)
  advance_pc(p, 4)
  copy(p) // (0x1006, b.c, 8)
  advance_line(p, -3) // line 5
  p.push((9).to_byte()) // fixed_advance_pc
  push_u16(p, 0x10)
  copy(p) // (0x1016, b.c, 5)
  p.push((8).to_byte()) // const_add_pc: (255-13)/14 = 17
  advance_line(p, 1) // line 6
  copy(p) // (0x1027, b.c, 6)
  ext_end_sequence(p)
  let (data, regions) = one_region(".debug_line", line_unit_v4(prologue, p))
  check_lines(data, regions, [
    (0x1000L, "a.c", 10),
    (0x1002L, "a.c", 8),
    (0x1006L, "b.c", 8),
    (0x1016L, "b.c", 5),
    (0x1027L, "b.c", 6),
  ])
}

test "line v4: define_file, unknown extended opcode skipped, sequence reset" {
  let prologue = std_prologue(-5, 14, 13)
  v4_tables(prologue, [], [("a.c", 0)])
  let p : Array[Byte] = []
  ext_set_address(p, 0x2000L)
  copy(p) // (0x2000, a.c, 1)
  // DW_LNE_define_file: "c.c", dir 0, mtime 0, size 0 -> file index 2 (1-based)
  p.push((0).to_byte())
  let name_bytes : Array[Byte] = []
  push_cstr(name_bytes, "c.c")
  push_uleb(p, 1 + name_bytes.length() + 3)
  p.push((3).to_byte())
  append(p, name_bytes)
  push_uleb(p, 0)
  push_uleb(p, 0)
  push_uleb(p, 0)
  set_file(p, 2)
  advance_pc(p, 2)
  copy(p) // (0x2002, c.c, 1)
  // unknown extended opcode 0x80 with 2 payload bytes: must be skipped
  p.push((0).to_byte())
  push_uleb(p, 3)
  p.push((0x80).to_byte())
  p.push((0xAA).to_byte())
  p.push((0xBB).to_byte())
  advance_pc(p, 1)
  copy(p) // (0x2003, c.c, 1)
  ext_end_sequence(p)
  // second sequence: registers reset (file back to 1, line back to 1)
  ext_set_address(p, 0x3000L)
  copy(p) // (0x3000, a.c, 1)
  ext_end_sequence(p)
  let (data, regions) = one_region(".debug_line", line_unit_v4(prologue, p))
  check_lines(data, regions, [
    (0x2000L, "a.c", 1),
    (0x2002L, "c.c", 1),
    (0x2003L, "c.c", 1),
    (0x3000L, "a.c", 1),
  ])
}

test "line v4: max_ops=2 op_index arithmetic (VLIW)" {
  let prologue = std_prologue(-5, 14, 13)
  prologue[1] = (2).to_byte() // maximum_operations_per_instruction = 2
  v4_tables(prologue, [], [("a.c", 0)])
  let p : Array[Byte] = []
  ext_set_address(p, 0x4000L)
  advance_pc(p, 3) // (0+3)/2 = 1 byte, op_index 1
  copy(p) // (0x4001, a.c, 1)
  advance_pc(p, 1) // (1+1)/2 = 1 byte, op_index 0
  copy(p) // (0x4002, a.c, 1)
  advance_line(p, 6) // line 7
  p.push((41).to_byte()) // special: adjusted 28 -> addr op +2 -> 1 byte, line -5 (emits row)
  ext_end_sequence(p)
  let (data, regions) = one_region(".debug_line", line_unit_v4(prologue, p))
  check_lines(data, regions, [
    (0x4001L, "a.c", 1),
    (0x4002L, "a.c", 1),
    (0x4003L, "a.c", 2),
  ])
}

test "line: truncated unit and program refused" {
  let prologue = std_prologue(-5, 14, 13)
  v4_tables(prologue, [], [("a.c", 0)])
  let p : Array[Byte] = []
  ext_set_address(p, 0x1000L)
  advance_pc(p, 128) // 2-byte uleb
  copy(p)
  ext_end_sequence(p)
  let unit = line_unit_v4(prologue, p)
  let (data, regions) = one_region(".debug_line", unit)
  // cut inside the unit_length-proclaimed body
  let (d1, r1) = one_region(".debug_line", prefix(unit, 8))
  expect_lines_truncated(d1, r1)
  // cut mid-opcode: trailing 00 01 01 (end_sequence) + last copy byte removed
  let (d2, r2) = one_region(".debug_line", prefix(unit, unit.length() - 4))
  expect_lines_truncated(d2, r2)
  // sanity: the uncut unit decodes
  check_lines(data, regions, [(0x1080L, "a.c", 1)])
}

test "line: missing section and out-of-bounds region refused" {
  let prologue = std_prologue(-5, 14, 13)
  v4_tables(prologue, [], [("a.c", 0)])
  let p : Array[Byte] = []
  ext_set_address(p, 0x1000L)
  copy(p)
  ext_end_sequence(p)
  let unit = line_unit_v4(prologue, p)
  let (data, _) = one_region(".debug_line", unit)
  expect_lines_invalid(data, [])
  let bad_regions : Array[@core.Region] = [
    { name: ".debug_line", offset: 100000L, size: 10L, vaddr: 0L, flags: "" },
  ]
  expect_lines_truncated(data, bad_regions)
}

// ---------------------------------------------------------------------------
// .debug_info / decode_funcs tests.

test "funcs v4: subprogram name + low_pc + high_pc offset, declaration skipped" {
  let ab : Array[Byte] = []
  push_abbrev(ab, 1, 0x11, true, [(0x03, 0x08)]) // compile_unit, name string
  push_abbrev(ab, 2, 0x2E, false, [(0x03, 0x08), (0x11, 0x01), (0x12, 0x06)])
  // subprogram declaration: name + DW_AT_declaration flag_present, no range
  push_abbrev(ab, 3, 0x2E, false, [(0x03, 0x08), (0x3C, 0x19)])
  ab.push((0).to_byte())
  let dies : Array[Byte] = []
  push_uleb(dies, 1)
  push_cstr(dies, "unit.c")
  push_uleb(dies, 2)
  push_cstr(dies, "foo")
  push_u64(dies, 0x3000L)
  push_u32(dies, 0x20) // high_pc as offset -> 0x3020
  push_uleb(dies, 3)
  push_cstr(dies, "decl") // no low/high: must not be emitted
  push_uleb(dies, 2)
  push_cstr(dies, "bar")
  push_u64(dies, 0x3040L)
  push_u32(dies, 0x10) // -> 0x3050
  push_uleb(dies, 0) // end compile_unit children
  push_uleb(dies, 0) // end CU
  let info = cu_v4(0, 8, dies)
  let (data, regions) = make_regions(
    [".debug_info", ".debug_abbrev"],
    [info, Bytes::from_array(ab)],
  )
  check_funcs(data, regions, [
    ("foo", 0x3000L, 0x3020L),
    ("bar", 0x3040L, 0x3050L),
  ])
}

test "funcs: subprogram nested in a namespace DIE is found" {
  let ab : Array[Byte] = []
  push_abbrev(ab, 1, 0x11, true, [(0x03, 0x08)])
  push_abbrev(ab, 2, 0x39, true, []) // DW_TAG_namespace, has children, no attrs
  push_abbrev(ab, 3, 0x2E, false, [(0x03, 0x08), (0x11, 0x01), (0x12, 0x06)])
  ab.push((0).to_byte())
  let dies : Array[Byte] = []
  push_uleb(dies, 1)
  push_cstr(dies, "u.c")
  push_uleb(dies, 2) // namespace
  push_uleb(dies, 3)
  push_cstr(dies, "nested")
  push_u64(dies, 0x7000L)
  push_u32(dies, 0x10)
  push_uleb(dies, 0) // end namespace children
  push_uleb(dies, 0) // end compile_unit children
  push_uleb(dies, 0) // end CU
  let info = cu_v4(0, 8, dies)
  let (data, regions) = make_regions(
    [".debug_info", ".debug_abbrev"],
    [info, Bytes::from_array(ab)],
  )
  check_funcs(data, regions, [("nested", 0x7000L, 0x7010L)])
}

