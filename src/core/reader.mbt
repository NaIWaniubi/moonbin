/// A bounds-checked cursor over an immutable byte buffer.
///
/// Every read returns `None` on end-of-buffer instead of panicking, so a
/// malformed file produces a `Truncated` refusal, never a crash or a guess.
pub struct Reader {
  data : Bytes
  mut pos : Int
}

///|
pub fn Reader::new(data : Bytes) -> Reader {
  { data, pos: 0 }
}

///|
pub fn Reader::position(self : Reader) -> Int {
  self.pos
}

///|
pub fn Reader::length(self : Reader) -> Int {
  self.data.length()
}

///|
pub fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.pos
}

///|
pub fn Reader::seek(self : Reader, pos : Int) -> Bool {
  if pos < 0 || pos > self.data.length() {
    return false
  }
  self.pos = pos
  true
}

///|
pub fn Reader::skip(self : Reader, n : Int) -> Bool {
  if n < 0 {
    return false
  }
  self.seek(self.pos + n)
}

///|
fn Reader::byte_at(self : Reader, i : Int) -> Int64 {
  self.data[i].to_int().to_int64()
}

///|
pub fn Reader::u8(self : Reader) -> Int? {
  if self.pos >= self.data.length() {
    return None
  }
  let v = self.data[self.pos].to_int()
  self.pos = self.pos + 1
  Some(v)
}

///|
pub fn Reader::i8(self : Reader) -> Int? {
  match self.u8() {
    Some(v) => Some(if v >= 128 { v - 256 } else { v })
    None => None
  }
}

///|
pub fn Reader::u16(self : Reader, endian : Endian) -> Int64? {
  if self.remaining() < 2 {
    return None
  }
  let a = self.byte_at(self.pos)
  let b = self.byte_at(self.pos + 1)
  self.pos = self.pos + 2
  Some(
    match endian {
      Little => (b << 8) | a
      Big => (a << 8) | b
    },
  )
}

///|
pub fn Reader::u32(self : Reader, endian : Endian) -> Int64? {
  if self.remaining() < 4 {
    return None
  }
  let a = self.byte_at(self.pos)
  let b = self.byte_at(self.pos + 1)
  let c = self.byte_at(self.pos + 2)
  let d = self.byte_at(self.pos + 3)
  self.pos = self.pos + 4
  Some(
    match endian {
      Little => (d << 24) | (c << 16) | (b << 8) | a
      Big => (a << 24) | (b << 16) | (c << 8) | d
    },
  )
}

///|
pub fn Reader::u64(self : Reader, endian : Endian) -> Int64? {
  if self.remaining() < 8 {
    return None
  }
  let mut v : Int64 = 0
  for i = 0; i < 8; i = i + 1 {
    let b = self.byte_at(self.pos + i)
    let shift = match endian {
      Little => i * 8
      Big => (7 - i) * 8
    }
    v = v | (b << shift)
  }
  self.pos = self.pos + 8
  Some(v)
}

///|
/// Read `n` raw bytes as a new buffer, advancing the cursor.
pub fn Reader::take(self : Reader, n : Int) -> Bytes? {
  if n < 0 || self.remaining() < n {
    return None
  }
  let start = self.pos
  let out = Bytes::makei(n, fn(i) { self.data[start + i] })
  self.pos = self.pos + n
  Some(out)
}

///|
/// A copy of `n` bytes without advancing the cursor.
pub fn Reader::peek(self : Reader, n : Int) -> Bytes? {
  if n < 0 || self.remaining() < n {
    return None
  }
  let start = self.pos
  Some(Bytes::makei(n, fn(i) { self.data[start + i] }))
}

///|
/// Read a NUL-terminated string, advancing past the terminator.
pub fn Reader::cstring(self : Reader) -> String? {
  let chars : Array[Char] = []
  while self.pos < self.data.length() {
    let b = self.data[self.pos].to_int()
    self.pos = self.pos + 1
    if b == 0 {
      return Some(String::from_array(chars))
    }
    chars.push(Char::from_int(b))
  }
  None
}