test "reader u8 and bounds" {
  let r = @core.Reader::new(Bytes::makei(2, fn(i) { (i + 1).to_byte() }))
  assert_eq(r.u8(), Some(1))
  assert_eq(r.u8(), Some(2))
  assert_eq(r.u8(), None)
}

test "reader u16/u32/u64 little endian" {
  let r = @core.Reader::new(Bytes::makei(8, fn(i) { (i + 1).to_byte() }))
  assert_eq(r.u16(Little), Some(0x0201))
  assert_eq(r.u32(Little), Some(0x06050403))
  let r2 = @core.Reader::new(Bytes::makei(8, fn(i) { (i + 1).to_byte() }))
  assert_eq(r2.u64(Little), Some(0x0807060504030201))
}

test "reader u16 big endian" {
  let r = @core.Reader::new(Bytes::makei(2, fn(i) { (i + 1).to_byte() }))
  assert_eq(r.u16(Big), Some(0x0102))
}

test "reader take and peek" {
  let r = @core.Reader::new(Bytes::makei(4, fn(i) { (i + 1).to_byte() }))
  assert_true(r.peek(2) != None)
  assert_eq(r.position(), 0)
  assert_true(r.take(2) != None)
  assert_eq(r.position(), 2)
  assert_eq(r.take(99), None)
}

test "reader cstring" {
  let data = Bytes::from_array([104, 105, 0].map(fn(x) { x.to_byte() }))
  let r = @core.Reader::new(data)
  assert_eq(r.cstring(), Some("hi"))
}

test "reader seek refuses out of range" {
  let r = @core.Reader::new(Bytes::makei(4, fn(i) { i.to_byte() }))
  assert_eq(r.seek(99), false)
  assert_eq(r.seek(2), true)
  assert_eq(r.position(), 2)
}