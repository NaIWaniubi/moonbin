/// Byte order of a multi-byte field.
pub(all) enum Endian {
  Little
  Big
} derive(Debug, Eq)

/// Why a parse stopped. Every variant is a refusal, never a guess.
pub(all) enum ParseError {
  /// Ran past the end of the buffer while reading `what`.
  Truncated(String)
  /// The leading magic did not match the format.
  BadMagic(String)
  /// A field held a value the format does not allow.
  Invalid(String)
} derive(Debug, Show)

/// A named region of the file (section / segment).
pub(all) struct Region {
  name : String
  /// File offset of the region's raw bytes.
  offset : Int64
  /// Size of the region in the file.
  size : Int64
  /// Virtual address the region maps to (0 when not loaded).
  vaddr : Int64
  /// Human-readable flags, e.g. "rx", "rw".
  flags : String
} derive(Debug)

/// A symbol table entry.
pub(all) struct Symbol {
  name : String
  value : Int64
  size : Int64
  /// e.g. "func", "object", "section", "file".
  kind : String
  /// e.g. "global", "local", "weak".
  bind : String
  /// Section index, or -1 for undefined / absolute.
  shndx : Int
} derive(Debug)

/// An imported symbol (PE import table / ELF dynamic).
pub(all) struct Import {
  /// Library / DLL name.
  library : String
  /// Symbol name, or "#ordinal" when imported by ordinal.
  name : String
} derive(Debug)

/// An exported symbol.
pub(all) struct Export {
  name : String
  ordinal : Int
  rva : Int64
} derive(Debug)