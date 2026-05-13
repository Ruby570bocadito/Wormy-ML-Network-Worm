#!/usr/bin/env python3
"""Compatibility shim — forwards to worm_core package."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from worm_core import main

if __name__ == "__main__":
    main()
