// Robustness fuzz: feed pseudo-random and mutated buffers to every parser and
// the disassembler. The contract is "refuse, never panic": if any call panicked
// the test process would crash, so a green run is evidence of no-panic over the
// whole mutation set. Deterministic PRNG keeps it reproducible.

fn xorshift(state : Int) -> Int {
  let mut x = state
  x = x ^ (x << 13)
  x = x ^ (x >> 17)
  x = x ^ (x << 5)
  x
}

fn rand_bytes(seed : Int, len : Int) -> Bytes {
  let mut s = seed
  Bytes::makei(len, fn(_) {
    s = xorshift(s)
    (s & 0xFF).to_byte()
  })
}

fn exercise(data : Bytes) -> Unit {
  let _ = @pe.parse(data)
  let _ = @elf.parse(data)
  let _ = @macho.parse(data)
  let _ = @disasm.disassemble(data, 0x1000L, 16)
  let _ = @format.detect(data)
}

test "fuzz: random buffers never panic" {
  let mut s = 0x12345678
  for i = 0; i < 400; i = i + 1 {
    s = xorshift(s)
    let len = s & 0x1FF
    exercise(rand_bytes(s, len))
  }
  assert_true(true)
}

test "fuzz: single-byte flips of a PE header never panic" {
  let base = Bytes::makei(64, fn(i) {
    if i == 0 {
      (0x4D).to_byte()
    } else if i == 1 {
      (0x5A).to_byte()
    } else {
      (0).to_byte()
    }
  })
  for pos = 0; pos < 64; pos = pos + 1 {
    for v = 0; v < 16; v = v + 1 {
      let mutated = Bytes::makei(64, fn(i) {
        if i == pos {
          (v * 17).to_byte()
        } else {
          base[i]
        }
      })
      exercise(mutated)
    }
  }
  assert_true(true)
}