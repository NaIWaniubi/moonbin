# moonbin frozen interfaces (v0.1)

All packages depend only on `src/core`. Do not edit `src/core`, `cmd/main`, or
another worker's package.

## core (already implemented, read src/core/*.mbt)

`Reader` (bounds-checked cursor over `Bytes`):
- `Reader::new(Bytes) -> Reader`
- `.position() / .length() / .remaining() -> Int`
- `.seek(Int) -> Bool`, `.skip(Int) -> Bool`
- `.u8() -> Int?`, `.i8() -> Int?`
- `.u16(Endian) / .u32(Endian) / .u64(Endian) -> Int64?`
- `.take(Int) -> Bytes?`, `.peek(Int) -> Bytes?`, `.cstring() -> String?`

`Endian { Little Big }`, `ParseError { Truncated(String) BadMagic(String) Invalid(String) }`
`Region { name offset size vaddr flags }`, `Symbol { name value size kind bind shndx }`,
`Import { library name }`, `Export { name ordinal rva }`  (all `pub(all)`).

## pe  -> `pub fn parse(Bytes) -> Result[Pe, @core.ParseError]`
`Pe { machine:Int, is64:Bool, entry:Int64, image_base:Int64,
      sections:Array[@core.Region], imports:Array[@core.Import],
      exports:Array[@core.Export], symbols:Array[@core.Symbol] }`
PE32 / PE32+ (magic 0x10b / 0x20b). DOS->e_lfanew, NT sig, COFF header,
optional header, section table, data directories (import=1, export=0).
RVA->file-offset via sections. Refuse (Invalid/Truncated), never panic.

## elf -> `pub fn parse(Bytes) -> Result[Elf, @core.ParseError]`
`Elf { class:Int(32|64), endian:@core.Endian, machine:Int, entry:Int64,
       sections:Array[@core.Region], segments:Array[@core.Region],
       symbols:Array[@core.Symbol], imports:Array[@core.Import],
       exports:Array[@core.Export] }`
ELF32/64, both endians. Header, program headers, section headers,
SHT_SYMTAB/DYNSYM + strtab. DT_NEEDED -> imports; defined dynsym -> exports.

## disasm -> x86-64
`pub fn decode(Bytes, addr:Int64) -> Result[Insn, @core.ParseError]`
`pub fn disassemble(Bytes, addr:Int64, count:Int) -> Array[Insn]`
`Insn { addr:Int64, len:Int, mnemonic:String, op_str:String, bytes:Bytes }`
Legacy prefixes, REX, one/two-byte opcode (0F), ModR/M, SIB, disp8/32, imm8/32.
Cover the common integer/SSE subset; unknown opcode -> Invalid (refuse), not guess.
Cross-check against python capstone on real .text bytes.