#!/usr/bin/env python3
"""Cross-check moonbin's direct callgraph against objdump -d on a real PE.

Every (caller, callee) edge moonbin reports for a direct `call rel32` must also
appear in objdump's disassembly of the same binary. Uses the native CLI, so it
exercises the shipped code path end to end.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "_build", "native", "release", "build", "cmd", "main", "main.exe")
SAMPLE = os.path.join(ROOT, "examples", "notepad.exe")


def cli_edges():
    out = subprocess.run([BIN, "callgraph", SAMPLE, "--json"],
                         capture_output=True, text=True, check=True).stdout
    return {(int(e["caller"], 16), int(e["callee"], 16)) for e in json.loads(out)}


def objdump_edges(base):
    out = subprocess.run(["objdump", "-d", SAMPLE],
                         capture_output=True, text=True, check=True).stdout
    edges = set()
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*call\s+(?:0x)?([0-9a-f]+)", line)
        if m:
            edges.add((int(m.group(1), 16) - base, int(m.group(2), 16) - base))
    return edges


def image_base():
    # objdump prints absolute VMAs; recover the base from start address - entry RVA.
    start = subprocess.run(["objdump", "-f", SAMPLE],
                           capture_output=True, text=True, check=True).stdout
    m = re.search(r"start address 0x([0-9a-f]+)", start)
    info = subprocess.run([BIN, "info", SAMPLE, "--json"],
                          capture_output=True, text=True, check=True).stdout
    entry = int(json.loads(info)["entry"], 16)
    return int(m.group(1), 16) - entry


def main():
    if not os.path.exists(BIN):
        print("build first: moon build --target native --release cmd/main")
        return 1
    cli = cli_edges()
    obj = objdump_edges(image_base())
    missing = cli - obj
    print(f"moonbin callgraph edges: {len(cli)}; objdump call edges: {len(obj)}")
    if not cli:
        print("FAIL: no edges produced")
        return 1
    if missing:
        print(f"FAIL: {len(missing)} edges not in objdump: {sorted(missing)[:5]}")
        return 1
    print(f"ANALYSIS CROSS-CHECK PASSED ({len(cli)}/{len(cli)} edges agree with objdump)")
    return 0


if __name__ == "__main__":
    sys.exit(main())