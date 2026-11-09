#!/usr/bin/env python3
"""Run COMPAS functional tests from both suite groups."""

import sys

sys.dont_write_bytecode = True
from runner import main

if __name__ == "__main__":
    raise SystemExit(main())
