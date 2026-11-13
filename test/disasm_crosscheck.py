#!/usr/bin/env python3
"""Capstone cross-check oracle for moonbin's x86-64 decoder (src/disasm).

Modes:
  emit                 print capstone (mnemonic, size) pairs for the fixed
                       bootstrap blob below (used to author the MoonBit test)
  verify               re-run capstone on every blob embedded in
                       src/disasm/crosscheck_test.mbt and compare against the
                       (mnemonic, len) pairs embedded there; exit 1 on mismatch
  notepad PATH [N]     extract .text from a PE file (read-only), disassemble
                       with capstone and print the longest prefix (<= N insns)
                       whose mnemonics are all in the decoder's supported set,
                       as paste-ready MoonBit test data.
  emit-mbt             (re)generate src/disasm/crosscheck_test.mbt from capstone

Usage (from the worktree root):
  python -I test/disasm_crosscheck.py emit
  python -I test/disasm_crosscheck.py verify
  python -I test/disasm_crosscheck.py notepad ../moonbin/examples/notepad.exe 60
"""
import re
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# Fixed bootstrap blob: known-good encodings covering the required subset.
BLOB_HEX = (
    "4889e5"          # mov rbp, rsp
    "4883ec20"        # sub rsp, 0x20
    "b801000000"      # mov eax, 1
    "c3"              # ret
    "90"              # nop
    "0f8410000000"    # je rel32
    "488b45f8"        # mov rax, [rbp-8]
    "55"              # push rbp
    "5d"              # pop rbp
    "488d0510000000"  # lea rax, [rip+0x10]
    "48ffc0"          # inc rax
    "48ffc8"          # dec rax
    "48f7d8"          # neg rax
    "48f7d0"          # not rax
    "4831c0"          # xor rax, rax
    "4801c0"          # add rax, rax
    "4829c0"          # sub rax, rax
    "4821c0"          # and rax, rax
    "4809c0"          # or rax, rax
    "4839c0"          # cmp rax, rax
    "4885c0"          # test rax, rax
    "486bc003"        # imul rax, rax, 3
    "48f7f8"          # idiv rax
    "48f7f0"          # div rax
    "48f7e1"          # mul rcx
    "48c1e004"        # shl rax, 4
    "48c1e804"        # shr rax, 4
    "48c1f804"        # sar rax, 4
    "48d1e0"          # shl rax, 1
    "d0e0"            # shl al, 1
    "48d3e0"          # shl rax, cl
    "48d1f0"          # sar rax, 1
    "e805000000"      # call rel32
    "ebfe"            # jmp rel8 (-2)
    "cc"              # int3
    "0fb6c0"          # movzx eax, al
    "0fbec0"          # movsx eax, al
    "480fb6c0"        # movzx rax, al
    "0fb7c0"          # movzx eax, ax
    "0fbfc0"          # movsx eax, ax
    "4863c0"          # movsxd rax, eax
    "0f94c0"          # sete al
    "0f95c0"          # setne al
    "0f44c0"          # cmove eax, eax
    "0f4fc0"          # cmovg eax, eax
    "0f28c1"          # movaps xmm0, xmm1
    "0f29c1"          # movaps xmm1, xmm0
    "660f6fc1"        # movdqa xmm0, xmm1
    "660f7fc1"        # movdqa xmm1, xmm0
    "f30f6fc1"        # movdqu xmm0, xmm1
    "f30f7fc1"        # movdqu xmm1, xmm0
    "660fefc1"        # pxor xmm0, xmm1
    "0f57c1"          # xorps xmm0, xmm1
    "660f57c1"        # xorpd xmm0, xmm1
    "f30f10c1"        # movss xmm0, xmm1
    "f20f10c1"        # movsd xmm0, xmm1
    "f30f11c1"        # movss xmm1, xmm0
    "66480f6ec0"      # movq xmm0, rax
    "66480f7ec0"      # movq rax, xmm0
    "f30f7ec1"        # movq xmm0, xmm1
    "488b042500000000"  # mov rax, [0] (SIB, no base)
    "488b0500000000"  # mov rax, [rip+0]
    "488b448d00"      # mov rax, [rbp+rcx*4+0]
    "488b8000010000"  # mov rax, [rax+0x100]
    "4150"            # push r8
    "4158"            # pop r8
    "4c89c0"          # mov rax, r8
    "48b88877665544332211"  # mov rax, 0x1122334455667788
    "6800010000"      # push 0x100
    "6a01"            # push 1
    "c20800"          # ret 8
    "0f1f4000"        # nop dword ptr [rax]
    "0f1f440000"      # nop dword ptr [rax+rax]
    "660f1f440000"    # nop word ptr [rax+rax]
    "f30f1efa"        # endbr64
    "4883f800"        # cmp rax, 0
    "803800"          # cmp byte ptr [rax], 0
    "813800010000"    # cmp dword ptr [rax], 0x100
    "48813800010000"  # cmp qword ptr [rax], 0x100
    "c60001"          # mov byte ptr [rax], 1
    "c70001000000"    # mov dword ptr [rax], 1
    "48c70001000000"  # mov qword ptr [rax], 1
    "8800"            # mov byte ptr [rax], al
    "8900"            # mov dword ptr [rax], eax
    "8a00"            # mov al, byte ptr [rax]
    "8b00"            # mov eax, dword ptr [rax]
    "b001"            # mov al, 1
    "66b80100"        # mov ax, 1
    "668900"          # mov word ptr [rax], ax
    "678b45f8"        # mov eax, [ebp-8] (addr32)
    "2e488b00"        # mov rax, cs:[rax]
    "64488b00"        # mov rax, fs:[rax]
    "f048ff00"        # lock inc qword ptr [rax]
    "4869c000010000"  # imul rax, rax, 0x100
    "0fafc1"          # imul eax, ecx
    "7405"            # je rel8
    "0f85f0ffffff"    # jne rel32 (-0x10)
    "ff2500000000"    # jmp qword ptr [rip+0]
    "ff1500000000"    # call qword ptr [rip+0]
    "ffd0"            # call rax
    "ffe0"            # jmp rax
    "ff30"            # push qword ptr [rax]
    "8f00"            # pop qword ptr [rax]
    "4899"            # cqo
    "99"              # cdq
    "c9"              # leave
    "4883c420"        # add rsp, 0x20
    "48894df8"        # mov [rbp-8], rcx
    "0f8400000000"    # je rel32 (0)
    "41ff5008"        # call qword ptr [r8+8]
    "48d1f8"          # sar rax, 1
    "48c1f83f"        # sar rax, 0x3f
    "0fb600"          # movzx eax, byte ptr [rax]
    "480fbe00"        # movsx rax, byte ptr [rax]
    "0f9f00"          # setg byte ptr [rax]
    "480f45c1"        # cmovne rax, rcx
    "660f28c1"        # movapd xmm0, xmm1
    "0f10c1"          # movups xmm0, xmm1
    "0f11c1"          # movups xmm1, xmm0
    "660f10c1"        # movupd xmm0, xmm1
    "f30f58c1"        # addss xmm0, xmm1
    "f20f58c1"        # addsd xmm0, xmm1
    "0f58c1"          # addps xmm0, xmm1
    "660f58c1"        # addpd xmm0, xmm1
    "f20f5ec1"        # divsd xmm0, xmm1
    "0f57c0"          # xorps xmm0, xmm0
    "660fefc0"        # pxor xmm0, xmm0
    "4831c9"          # xor rcx, rcx
    "85c0"            # test eax, eax
    "83f800"          # cmp eax, 0
    "83780800"        # cmp dword ptr [rax+8], 0
    "488b4010"        # mov rax, [rax+0x10]
    "4c8b4010"        # mov r8, [rax+0x10]
    "4a8b04e0"        # mov rax, [rax+r12*8]
    "488d4c2408"      # lea rcx, [rsp+8]
    "4883ec28"        # sub rsp, 0x28
    "4883c428"        # add rsp, 0x28
    "e900000000"      # jmp rel32 (0)
    "0f05"            # syscall
)

# Mnemonics the MoonBit decoder supports (must mirror src/disasm).
SUPPORTED = set("""
adc add and bswap bt btc btr bts call cbw cdq cdqe clc cld cli cmc cmp cqo
cwd cwde dec div endbr64 hlt idiv imul inc int int3 ja jae jb jbe je jg jge
jl jle jmp jne jno jnp jns jo jp js ldmxcsr lea leave lfence mfence mov movapd
movaps movd movdqa movdqu movq movsd movss movsx movsxd movupd movups movzx
mul neg nop not or pand pandn por pop popf popfq pxor push pushf pushfq rcl
rcr ret rol ror sar sbb sfence shl shr stc sti sub syscall sysret test ucomisd
ucomiss comiss comisd xadd xchg xor xorpd xorps
""".split())
for _cc in ("o no b ae e ne be a s ns p np l ge le g".split()):
    SUPPORTED.add("j" + _cc)
    SUPPORTED.add("set" + _cc)
    SUPPORTED.add("cmov" + _cc)
for _op in ("add mul sub div min max".split()):
    for _suf in ("ps pd ss sd".split()):
        SUPPORTED.add(_op + _suf)


def disasm(blob: bytes, base: int = 0x1000):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return [(i.mnemonic, i.size) for i in md.disasm(blob, base)]


def cmd_emit():
    pairs = disasm(bytes.fromhex(BLOB_HEX))
    for mn, sz in pairs:
        print(f"{mn}:{sz}")
    print(f"# {len(pairs)} instructions, blob {len(BLOB_HEX)//2} bytes")


def extract_blocks(mbt_text: str):
    """Yield (blob_hex, [(mnemonic, len), ...]) per test block in the file."""
    blobs = re.findall(r'let blob_hex\s*=\s*"([0-9a-fA-F]+)"', mbt_text)
    arrays = re.findall(
        r'let expected\s*:\s*Array\[\(String,\s*Int\)\]\s*=\s*\[(.*?)\]',
        mbt_text, re.S)
    if len(blobs) != len(arrays):
        raise SystemExit(f"parse error: {len(blobs)} blobs vs {len(arrays)} expected arrays")
    for hexstr, arr in zip(blobs, arrays):
        pairs = [(m, int(n)) for m, n in re.findall(r'\("([a-z0-9 ]+)",\s*(\d+)\)', arr)]
        yield hexstr, pairs


def cmd_verify():
    root = Path(__file__).resolve().parent.parent
    mbt = root / "src" / "disasm" / "crosscheck_test.mbt"
    text = mbt.read_text(encoding="utf-8")
    total = agree = 0
    ok = True
    for bi, (hexstr, expected) in enumerate(extract_blocks(text)):
        got = disasm(bytes.fromhex(hexstr))
        n = max(len(got), len(expected))
        for i in range(n):
            total += 1
            g = got[i] if i < len(got) else None
            e = expected[i] if i < len(expected) else None
            if g == e:
                agree += 1
            else:
                ok = False
                print(f"block {bi} insn {i}: capstone={g} moonbit-test={e}")
        if len(got) != len(expected):
            ok = False
            print(f"block {bi}: count mismatch capstone={len(got)} test={len(expected)}")
    pct = 100.0 * agree / total if total else 0.0
    print(f"capstone agreement: {agree}/{total} ({pct:.1f}%)")
    if not ok or total == 0:
        raise SystemExit(1)
    print("CROSSCHECK PASS")


def pe_text(data: bytes):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("not a PE file")
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    for i in range(nsec):
        off = sec_off + 40 * i
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        if name == ".text":
            raw_size, raw_ptr = struct.unpack_from("<II", data, off + 16)
            return data[raw_ptr:raw_ptr + raw_size]
    raise SystemExit("no .text section")


def cmd_notepad(path: str, n: int):
    data = Path(path).read_bytes()
    text = pe_text(data)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    prefix = []
    consumed = 0
    for ins in md.disasm(text[:4096], 0x140001000):
        if len(prefix) >= n or ins.mnemonic.replace("lock ", "") not in SUPPORTED:
            break
        prefix.append((ins.mnemonic, ins.size))
        consumed += ins.size
    blob = text[:consumed].hex()
    print(f"// notepad .text prefix: {len(prefix)} instructions, {consumed} bytes")
    print(f'let blob_hex = "{blob}"')
    print("let expected : Array[(String, Int)] = [")
    for mn, sz in prefix:
        print(f'  ("{mn}", {sz}),')
    print("]")


MBT_HEADER = """// Generated by test/disasm_crosscheck.py (mode: emit-mbt). DO NOT EDIT.
// Expected (mnemonic, len) pairs come from python capstone
// Cs(CS_ARCH_X86, CS_MODE_64). Re-check with:
//   python -I test/disasm_crosscheck.py verify

fn hex_val(v : Int) -> Int {
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 87
  } else if v >= 65 && v <= 70 {
    v - 55
  } else {
    0
  }
}

fn hex_to_bytes(s : String) -> Bytes {
  Bytes::makei(s.length() / 2, fn(i) {
    (hex_val(s[2 * i].to_int()) * 16 + hex_val(s[2 * i + 1].to_int())).to_byte()
  })
}

fn assert_insn_list(
  data : Bytes,
  base : Int64,
  expected : Array[(String, Int)]
) -> Unit raise {
  let insns = disassemble(data, base, expected.length())
  assert_eq(insns.length(), expected.length())
  let mut a = base
  let mut off = 0
  for i = 0; i < expected.length(); i = i + 1 {
    let (mn, sz) = expected[i]
    assert_eq(insns[i].mnemonic, mn)
    assert_eq(insns[i].len, sz)
    assert_eq(insns[i].addr, a)
    assert_eq(insns[i].bytes.length(), sz)
    a = a + sz.to_int64()
    off = off + sz
  }
  assert_eq(off, data.length())
}
"""


def mbt_block(title: str, hexstr: str, pairs) -> str:
    lines = [f'test "{title}" {{', f'  let blob_hex = "{hexstr}"',
             '  let expected : Array[(String, Int)] = [']
    for mn, sz in pairs:
        lines.append(f'    ("{mn}", {sz}),')
    lines.append('  ]')
    lines.append('  assert_insn_list(hex_to_bytes(blob_hex), 0x1000L, expected)')
    lines.append('}')
    return "\n".join(lines)


def cmd_emit_mbt():
    root = Path(__file__).resolve().parent.parent
    pairs = disasm(bytes.fromhex(BLOB_HEX))
    if sum(s for _, s in pairs) != len(BLOB_HEX) // 2:
        raise SystemExit("capstone did not consume the whole fixed blob")
    parts = [MBT_HEADER,
             mbt_block(f"capstone crosscheck: fixed blob ({len(pairs)} insns)",
                       BLOB_HEX, pairs)]
    notepad = root.parent / "moonbin" / "examples" / "notepad.exe"
    if notepad.exists():
        text = pe_text(notepad.read_bytes())
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        prefix, consumed = [], 0
        for ins in md.disasm(text[:4096], 0x140001000):
            if len(prefix) >= 60 or ins.mnemonic.replace("lock ", "") not in SUPPORTED:
                break
            prefix.append((ins.mnemonic, ins.size))
            consumed += ins.size
        parts.append(mbt_block(
            f"capstone crosscheck: notepad .text prefix ({len(prefix)} insns)",
            text[:consumed].hex(), prefix))
    else:
        print(f"warning: {notepad} not found, skipping notepad block")
    out = root / "src" / "disasm" / "crosscheck_test.mbt"
    out.write_text("\n\n".join(parts) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    mode = sys.argv[1]
    if mode == "emit":
        cmd_emit()
    elif mode == "verify":
        cmd_verify()
    elif mode == "notepad":
        cmd_notepad(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 60)
    elif mode == "emit-mbt":
        cmd_emit_mbt()
    else:
        raise SystemExit(f"unknown mode: {mode}")


if __name__ == "__main__":
    main()