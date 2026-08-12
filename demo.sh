#!/usr/bin/env bash
# ==============================================================================
# Demo script launcher for DNS Spoofing Simulation Framework
# ==============================================================================
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
    echo "[!] Virtual environment not found. Running setup.sh..."
    ./setup.sh
fi

echo "======================================================================"
echo "🎯 Starting DNS Spoofing Framework - DEMO MODE"
echo "   No root privileges required - safe simulation only"
echo "======================================================================"

./venv/bin/python3 scripts/demo.py
