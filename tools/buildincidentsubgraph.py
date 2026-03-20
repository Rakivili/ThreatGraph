#!/usr/bin/env python3
"""Compatibility wrapper for build_incident_subgraphs.py."""

from pathlib import Path
import runpy


if __name__ == "__main__":
    target = Path(__file__).with_name("build_incident_subgraphs.py")
    runpy.run_path(str(target), run_name="__main__")
