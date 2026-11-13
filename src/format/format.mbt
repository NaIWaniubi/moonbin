/// Container formats moonbin can identify by leading magic.
pub(all) enum Format {
  Pe
  Elf
  MachO
  Unknown
} derive(Debug, Eq)

///|
fn b(data : Bytes, i : Int) -> Int {
  data[i].to_int()
}

///|
/// Identify the container from its magic bytes. Detection never fails; an
/// unrecognized buffer is `Unknown`, and the caller refuses it explicitly.
pub fn detect(data : Bytes) -> Format {
  let n = data.length()
  if n >= 2 && b(data, 0) == 0x4D && b(data, 1) == 0x5A {
    return Pe
  }
  if n >= 4 && b(data, 0) == 0x7F && b(data, 1) == 0x45 && b(data, 2) == 0x4C &&
    b(data, 3) == 0x46 {
    return Elf
  }
  if n >= 4 {
    let m = (b(data, 0) << 24) | (b(data, 1) << 16) | (b(data, 2) << 8) | b(data, 3)
    if m == 0xFEEDFACE || m == 0xFEEDFACF || m == 0xCEFAEDFE || m == 0xCFFAEDFE {
      return MachO
    }
  }
  Unknown
}

///|
pub fn name(f : Format) -> String {
  match f {
    Pe => "PE"
    Elf => "ELF"
    MachO => "Mach-O"
    Unknown => "unknown"
  }
}