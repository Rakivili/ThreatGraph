#!/usr/bin/env python3
"""
Read scalar values from a simple nested YAML file by dot path.

This helper intentionally supports the subset used by threatgraph configs:
- nested mapping keys with space indentation
- scalar values on the same line
- ignores multi-line block values such as query: >-
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Dict, List, Tuple


LINE_RE = re.compile(r"^(\s*)([^:\s][^:]*):(?:\s*(.*))?$")
BLOCK_MARKERS = {"|", ">", "|-", ">-"}


def parse_scalars(path: str) -> Dict[str, str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    scalars: Dict[str, str] = {}
    stack: List[Tuple[int, str]] = []
    skip_block_indent = -1

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if skip_block_indent >= 0:
            if indent > skip_block_indent:
                continue
            skip_block_indent = -1

        m = LINE_RE.match(line)
        if not m:
            continue

        indent = len(m.group(1))
        key = m.group(2).strip()
        value = (m.group(3) or "").strip()

        while stack and stack[-1][0] >= indent:
            stack.pop()

        path_key = ".".join([k for _, k in stack] + [key])

        if value == "":
            stack.append((indent, key))
            continue

        if value in BLOCK_MARKERS:
            skip_block_indent = indent
            continue

        if " #" in value:
            value = value.split(" #", 1)[0].rstrip()

        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]

        scalars[path_key] = value

    return scalars


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    p.add_argument("--path", required=True, help="dot path, e.g. threatgraph.output.clickhouse.url")
    args = p.parse_args()

    data = parse_scalars(args.config)
    value = data.get(args.path, "")
    sys.stdout.write(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
