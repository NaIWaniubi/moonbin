/// Pure analysis helpers over raw bytes: printable-string extraction and
/// Shannon entropy. Everything here is bounds-safe and panic-free: hostile
/// offsets/sizes are clamped, empty input yields neutral results.

/// A run of ASCII printable bytes (0x20..0x7E) found in a buffer.
pub(all) struct StringHit {
  /// File offset of the first byte of the run.
  offset : Int64
  /// The run's text (ASCII only).
  text : String
} derive(Debug, Eq)

/// Shannon entropy of one named region.
pub(all) struct SectionEntropy {
  name : String
  /// Entropy in bits per byte, 0..8.
  entropy : Float
} derive(Debug, Eq)

/// ASCII printable: space (0x20) through tilde (0x7E). Tab, newline and DEL
/// are deliberately excluded, matching the strict `strings` convention.
fn is_printable(b : Int) -> Bool {
  b >= 0x20 && b <= 0x7E
}

///|
/// Extract all ASCII printable runs of length >= `min_len`, in file order.
/// `min_len` below 1 is clamped to 1 (empty runs are never reported).
pub fn strings(data : Bytes, min_len : Int) -> Array[StringHit] {
  let out : Array[StringHit] = []
  let need = if min_len < 1 {
    1
  } else {
    min_len
  }
  let n = data.length()
  let mut i = 0
  while i < n {
    if is_printable(data[i].to_int()) {
      let start = i
      let chars : Array[Char] = []
      while i < n && is_printable(data[i].to_int()) {
        chars.push(data[i].to_int().unsafe_to_char())
        i = i + 1
      }
      if i - start >= need {
        out.push({ offset: start.to_int64(), text: String::from_array(chars) })
      }
    } else {
      i = i + 1
    }
  }
  out
}

///|
/// Shannon entropy of the whole buffer in bits per byte (0..8).
/// Empty input has entropy 0. Computed in double precision so that exact
/// cases (constant data -> 0, uniform 256 symbols -> 8) stay exact.
pub fn entropy(data : Bytes) -> Float {
  Float::from_double(entropy_range(data, 0, data.length()))
}

/// Entropy of `data[start .. start+len]`; caller guarantees the range is
/// in bounds. `len <= 0` yields 0.
fn entropy_range(data : Bytes, start : Int, len : Int) -> Double {
  if len <= 0 {
    return 0.0
  }
  let hist : Array[Int] = Array::make(256, 0)
  for i = start; i < start + len; i = i + 1 {
    let b = data[i].to_int()
    hist[b] = hist[b] + 1
  }
  let total = len.to_double()
  let mut h = 0.0
  for c in hist {
    if c > 0 {
      let p = c.to_double() / total
      h = h - p * @math.log2(p)
    }
  }
  h
}

///|
/// Per-region entropy for a section/segment table. Offsets and sizes are
/// clamped to the buffer in 64-bit space (no wraparound on hostile values);
/// a region that ends up empty gets entropy 0. Never panics.
pub fn section_entropy(
  data : Bytes,
  sections : Array[@core.Region]
) -> Array[SectionEntropy] {
  let out : Array[SectionEntropy] = []
  let n64 = data.length().to_int64()
  for r in sections {
    let off = if r.offset < 0L {
      0L
    } else if r.offset > n64 {
      n64
    } else {
      r.offset
    }
    let size = if r.size < 0L {
      0L
    } else {
      r.size
    }
    // Compare before adding so off + size cannot overflow Int64.
    let end = if size > n64 - off {
      n64
    } else {
      off + size
    }
    let start = off.to_int()
    let len = (end - off).to_int()
    out.push({ name: r.name, entropy: Float::from_double(entropy_range(data, start, len)) })
  }
  out
}