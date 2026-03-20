#!/usr/bin/env python3
"""Compatibility wrapper for make_viewer.py."""

from pathlib import Path
import runpy


if __name__ == "__main__":
    target = Path(__file__).with_name("make_viewer.py")
    runpy.run_path(str(target), run_name="__main__")
