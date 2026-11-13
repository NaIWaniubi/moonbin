fn main {
  let r = @core.Reader::new(Bytes::makei(4, fn(i) { (i + 1).to_byte() }))
  println("moonbin core ok, len=\{r.length()}")
}