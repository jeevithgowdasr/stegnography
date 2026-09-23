#!/usr/bin/env bash
# ====================================================================
# StegoCrypt Desktop Application Launcher (macOS / Linux)
# ====================================================================

echo "[*] Starting Image Encryption & Steganography Desktop Application..."

# Activate virtual environment if available
if [ -d "venv" ]; then
    echo "[*] Activating virtual environment (venv)..."
    source venv/bin/activate
elif [ -d ".venv" ]; then
    echo "[*] Activating virtual environment (.venv)..."
    source .venv/bin/activate
fi

python3 gui.py
