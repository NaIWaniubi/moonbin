#!/usr/bin/env python3
"""Reproduce BENCHMARKS.md: best-of-3 wall time for moonbin / objdump / capstone.

capstone is optional; if absent only moonbin and objdump are timed.
"""
import os
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "_build", "native", "release", "build", "cmd", "main", "main.exe")
SAMPLE = os.path.join(ROOT, "examples", "notepad.exe")
TEXT_OFF, TEXT_SIZE = 0x1000, 0x28000


def best_ms(fn):
    best = 1e9
    for _ in range(3):
        a = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - a)
    return best * 1000


def main():
    if not os.path.exists(BIN):
        print("build first: moon build --target native --release cmd/main")
        return 1
    mb = best_ms(lambda: subprocess.run([BIN, "disasm", SAMPLE, "--count", "200000"],
                                        capture_output=True))
    ob = best_ms(lambda: subprocess.run(["objdump", "-d", SAMPLE], capture_output=True))
    print(f"moonbin disasm full .text : {mb:7.1f} ms")
    print(f"objdump -d (whole file)   : {ob:7.1f} ms")
    try:
        import capstone
    except ImportError:
        print("capstone not installed; skipping")
        return 0
    data = open(SAMPLE, "rb").read()[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True
    cb = best_ms(lambda: sum(1 for _ in md.disasm(data, TEXT_OFF)))
    print(f"capstone skipdata .text   : {cb:7.1f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())