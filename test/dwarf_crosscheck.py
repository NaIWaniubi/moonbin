#!/usr/bin/env python3
"""Cross-check moonbin's DWARF source mapping against objdump on a real binary.

The fixture examples/dbg.exe is compiled from examples/dbg.c with gcc -g, so it
carries genuine DWARF. Line rows must equal objdump --dwarf=decodedline, and the
subprogram set must equal {add, main} with sane ranges.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "_build", "native", "release", "build", "cmd", "main", "main.exe")
SAMPLE = os.path.join(ROOT, "examples", "dbg.exe")


def cli():
    out = subprocess.run([BIN, "dwarf", SAMPLE, "--json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def objdump_lines():
    out = subprocess.run(["objdump", "--dwarf=decodedline", SAMPLE],
                         capture_output=True, text=True, check=True).stdout
    rows = set()
    for line in out.splitlines():
        m = re.match(r"\s*(\S+)\s+(\d+)\s+0x([0-9a-f]+)", line)
        if m:
            rows.add((int(m.group(3), 16), m.group(1), int(m.group(2))))
    return rows


def main():
    if not os.path.exists(BIN):
        print("build first: moon build --target native --release cmd/main")
        return 1
    r = cli()
    mine = {(int(x["addr"], 16), x["file"], x["line"]) for x in r["lines"]}
    obj = objdump_lines()
    if not mine:
        print("FAIL: no line rows")
        return 1
    if mine != obj:
        print(f"FAIL: line mismatch mine={len(mine)} obj={len(obj)}; "
              f"only-mine={sorted(mine - obj)[:3]} only-obj={sorted(obj - mine)[:3]}")
        return 1
    names = {f["name"] for f in r["funcs"]}
    if names != {"add", "main"}:
        print(f"FAIL: subprograms {names} != {{add, main}}")
        return 1
    for f in r["funcs"]:
        if not (int(f["low"], 16) < int(f["high"], 16)):
            print(f"FAIL: bad range for {f['name']}")
            return 1
    print(f"DWARF CROSS-CHECK PASSED ({len(mine)} line rows == objdump; funcs add/main)")
    return 0


if __name__ == "__main__":
    sys.exit(main())