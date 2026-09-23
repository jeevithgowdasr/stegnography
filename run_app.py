#!/usr/bin/env python3
"""
Launcher script for StegoCrypt GUI Application.
Run directly with: python run_app.py
"""

import os
import sys

# Ensure src directory is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from image_stego.gui.app import launch_gui

if __name__ == "__main__":
    launch_gui()
