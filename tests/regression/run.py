#!/usr/bin/env python3
"""Run functional regression suites."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runner import main

if __name__ == "__main__":
    raise SystemExit(main(default_suite="regression"))
