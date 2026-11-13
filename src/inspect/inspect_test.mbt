// Contract tests for the inspect package (frozen task spec):
//   strings  -> ASCII printable (0x20..0x7E) runs of length >= min_len
//   entropy  -> Shannon entropy over the byte histogram, 0..8 bits
//   section_entropy -> per-region entropy, bounds-clamped, never panics
// All fixtures are deterministic and built in-test.

fn bytes_of(xs : Array[Int]) -> Bytes {
  Bytes::makei(xs.length(), fn(i) { xs[i].to_byte() })
}

/// The standard mixed blob used by several strings tests:
///   00 "Hello" 00 "a" FF "World!" 7F "xy"
/// offsets: Hello=1, a=7, World!=9, xy=16
fn mixed_blob() -> Bytes {
  bytes_of([
    0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x61, 0xFF, 0x57, 0x6F, 0x72,
    0x6C, 0x64, 0x21, 0x7F, 0x78, 0x79,
  ])
}

test "strings finds printable runs with exact offsets" {
  let hits = @inspect.strings(mixed_blob(), 1)
  assert_eq(hits.length(), 4)
  assert_eq(hits[0], { offset: 1L, text: "Hello" })
  assert_eq(hits[1], { offset: 7L, text: "a" })
  assert_eq(hits[2], { offset: 9L, text: "World!" })
  assert_eq(hits[3], { offset: 16L, text: "xy" })
}

test "strings min_len filters short runs" {
  let hits = @inspect.strings(mixed_blob(), 4)
  assert_eq(hits.length(), 2)
  assert_eq(hits[0], { offset: 1L, text: "Hello" })
  assert_eq(hits[1], { offset: 9L, text: "World!" })
}

test "strings run of exactly min_len is included" {
  let hits5 = @inspect.strings(mixed_blob(), 5)
  assert_eq(hits5.length(), 2)
  assert_eq(hits5[0].text, "Hello")
  let hits6 = @inspect.strings(mixed_blob(), 6)
  assert_eq(hits6.length(), 1)
  assert_eq(hits6[0], { offset: 9L, text: "World!" })
  assert_eq(@inspect.strings(mixed_blob(), 7).length(), 0)
}

test "strings empty input yields no hits" {
  assert_eq(@inspect.strings(Bytes::makei(0, fn(_) { (0).to_byte() }), 1).length(), 0)
}

test "strings non-printable-only input yields no hits" {
  let data = bytes_of([0x00, 0x01, 0x09, 0x0A, 0x0D, 0x7F, 0x80, 0xFF])
  assert_eq( @inspect.strings(data, 1).length(), 0)
}

test "strings unterminated run at end of buffer is captured" {
  let data = bytes_of([0x00, 0x00, 0x61, 0x62, 0x63])
  let hits = @inspect.strings(data, 3)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0], { offset: 2L, text: "abc" })
}

test "strings nonpositive min_len clamps to 1" {
  let a = @inspect.strings(mixed_blob(), 0)
  let b = @inspect.strings(mixed_blob(), -3)
  let c = @inspect.strings(mixed_blob(), 1)
  assert_eq(a.length(), 4)
  assert_eq(b.length(), 4)
  assert_eq(a, c)
}

test "strings space is printable but tab and DEL break runs" {
  let spaces = bytes_of([0x20, 0x20, 0x20, 0x20])
  let hits = @inspect.strings(spaces, 4)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0], { offset: 0L, text: "    " })
  // "ab\tcd" -> two runs; DEL (0x7F) also splits
  let split = bytes_of([0x61, 0x62, 0x09, 0x63, 0x64, 0x7F, 0x65, 0x66])
  let hs = @inspect.strings(split, 2)
  assert_eq(hs.length(), 3)
  assert_eq(hs[0].text, "ab")
  assert_eq(hs[1].text, "cd")
  assert_eq(hs[2].text, "ef")
}

test "strings high bytes break runs (ASCII only)" {
  let data = bytes_of([0x61, 0x62, 0xE9, 0x63, 0x64])
  let hits = @inspect.strings(data, 2)
  assert_eq(hits.length(), 2)
  assert_eq(hits[0].offset, 0L)
  assert_eq(hits[1].offset, 3L)
}

test "entropy of empty input is zero" {
  assert_eq(@inspect.entropy(Bytes::makei(0, fn(_) { (0).to_byte() })), 0.0)
}

test "entropy of all-zero bytes is zero" {
  assert_eq(@inspect.entropy(Bytes::makei(1024, fn(_) { (0).to_byte() })), 0.0)
}

test "entropy of constant data is zero" {
  assert_eq(@inspect.entropy(bytes_of([0x61, 0x61, 0x61, 0x61])), 0.0)
  assert_eq(@inspect.entropy(Bytes::makei(300, fn(_) { (0xFF).to_byte() })), 0.0)
  assert_eq(@inspect.entropy(bytes_of([0x42])), 0.0)
}

test "entropy of uniform 256-byte histogram is exactly 8" {
  let data = Bytes::makei(256, fn(i) { i.to_byte() })
  assert_eq(@inspect.entropy(data), 8.0)
}

test "entropy of two equally frequent symbols is exactly 1" {
  let data = Bytes::makei(100, fn(i) { (if i % 2 == 0 { 0x61 } else { 0x62 }).to_byte() })
  assert_eq(@inspect.entropy(data), 1.0)
  assert_eq(@inspect.entropy(bytes_of([0x00, 0x01])), 1.0)
}

test "entropy of mixed data stays within 0..8 and is high" {
  // Deterministic LCG byte stream: near-uniform histogram.
  let mut state = 12345
  let data = Bytes::makei(4096, fn(_) {
    state = (state * 1103515245 + 12345) & 0x7FFFFFFF
    ((state >> 16) & 0xFF).to_byte()
  })
  let e = @inspect.entropy(data)
  assert_true(e >= 0.0)
  assert_true(e <= 8.0)
  assert_true(e > 7.0)
}

test "entropy of skewed data is low but positive" {
  // 90% 'a', 10% 'b' -> H = -0.9*log2(0.9) - 0.1*log2(0.1) ~ 0.469
  let data = Bytes::makei(100, fn(i) { (if i < 90 { 0x61 } else { 0x62 }).to_byte() })
  let e = @inspect.entropy(data)
  assert_true(e > 0.0)
  assert_true(e < 1.0)
}

fn region(name : String, offset : Int64, size : Int64) -> @core.Region {
  { name, offset, size, vaddr: 0L, flags: "r" }
}

test "section_entropy computes per-region entropy" {
  // 256 zero bytes followed by the uniform 0..255 histogram.
  let data = Bytes::makei(512, fn(i) { (if i < 256 { 0 } else { i - 256 }).to_byte() })
  let regs = [region("zeros", 0L, 256L), region("uniform", 256L, 256L)]
  let es = @inspect.section_entropy(data, regs)
  assert_eq(es.length(), 2)
  assert_eq(es[0].name, "zeros")
  assert_eq(es[0].entropy, 0.0)
  assert_eq(es[1].name, "uniform")
  assert_eq(es[1].entropy, 8.0)
}

test "section_entropy empty region list yields empty result" {
  let data = bytes_of([0x61, 0x62])
  assert_eq( @inspect.section_entropy(data, []).length(), 0)
}

test "section_entropy clamps out-of-bounds regions without panic" {
  let data = Bytes::makei(256, fn(i) { i.to_byte() })
  let regs = [
    region("neg-offset", -5L, 10L),     // clamped to [0, 5)
    region("past-eof", 300L, 10L),      // empty slice -> 0
    region("oversize", 250L, 1000L),    // clamped to [250, 256)
    region("neg-size", 10L, -3L),       // empty slice -> 0
    region("whole", 0L, 256L),          // full uniform -> 8
  ]
  let es = @inspect.section_entropy(data, regs)
  assert_eq(es.length(), 5)
  assert_eq(es[1].entropy, 0.0)
  assert_eq(es[3].entropy, 0.0)
  assert_eq(es[4].entropy, 8.0)
  assert_true(es[0].entropy >= 0.0)
  assert_true(es[0].entropy <= 8.0)
  assert_true(es[2].entropy >= 0.0)
  assert_true(es[2].entropy <= 8.0)
}