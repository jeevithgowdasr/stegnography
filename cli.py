#!/usr/bin/env python3
"""
CLI launcher script for StegoCrypt.
Run directly with: python cli.py <subcommand> [options]
"""

import os
import sys

# Ensure src directory is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from image_stego.cli.main import main

if __name__ == "__main__":
    main()
