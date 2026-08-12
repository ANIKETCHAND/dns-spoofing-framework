#!/usr/bin/env bash
# ==============================================================================
# Setup script for DNS Spoofing Simulation Framework on Kali Linux / Debian
# ==============================================================================
set -e

echo "======================================================================"
echo "  🛡️  DNS Spoofing Simulation Framework - Kali Linux Setup"
echo "======================================================================"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "[+] Detected OS: $PRETTY_NAME"
    IS_KALI=false
    if [[ "$ID" == "kali" ]] || [[ "$ID" == "debian" ]] || [[ "$ID" == "ubuntu" ]]; then
        IS_KALI=true
        echo "[+] Kali/Debian/Ubuntu detected - using apt package manager"
    fi
else
    echo "[!] Cannot detect OS. Proceeding with generic setup..."
    IS_KALI=false
fi

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[!] python3 could not be found. Please install Python 3."
    if [ "$IS_KALI" = true ]; then
        echo "    On Kali/Debian: sudo apt-get install python3 python3-pip python3-venv"
    fi
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "[+] Python version: $PYTHON_VERSION"

# Check Python version (need 3.8+)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo "[!] Python 3.8+ required. Current: $PYTHON_VERSION"
    exit 1
fi

# Install system dependencies
if [ "$IS_KALI" = true ]; then
    echo "[+] Updating package index and installing system dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        python3-pip \
        python3-venv \
        python3-dev \
        libpcap-dev \
        build-essential \
        tcpdump \
        net-tools \
        iproute2 \
        2>/dev/null || {
            echo "[!] Some packages may have failed to install. Continuing..."
        }
else
    echo "[+] Non-Debian system detected. Skipping apt package installation."
    echo "    Please ensure you have: python3-venv, libpcap-dev, build-essential, tcpdump"
fi

# Verify libpcap is available for Scapy
if ! python3 -c "import ctypes.util; print(ctypes.util.find_library('pcap'))" 2>/dev/null | grep -q pcap; then
    echo "[!] Warning: libpcap not found in library path. Live packet capture may not work."
    if [ "$IS_KALI" = true ]; then
        echo "    Try: sudo apt-get install libpcap-dev libpcap0.8"
    fi
fi

# Create virtualenv
if [ ! -d "venv" ]; then
    echo "[+] Creating Python virtual environment (venv)..."
    python3 -m venv venv
else
    echo "[+] Python virtual environment (venv) already exists."
fi

# Activate venv and install dependencies
echo "[+] Upgrading pip and installing Python dependencies..."
./venv/bin/python3 -m pip install --upgrade pip setuptools wheel -q
./venv/bin/python3 -m pip install -r requirements.txt pytest httpx -q

# Verify Scapy installation with libpcap
echo "[+] Verifying Scapy installation..."
./venv/bin/python3 -c "
try:
    from scapy.all import conf, get_if_list
    conf.verb = 0
    interfaces = get_if_list()
    print(f'[+] Scapy OK. Available interfaces: {interfaces}')
except Exception as e:
    print(f'[!] Scapy import failed: {e}')
    exit(1)
" 2>/dev/null || {
    echo "[!] Scapy verification failed. Live capture may not work."
    echo "    This is OK for simulation mode only."
}

# Make launcher scripts executable
chmod +x run.sh demo.sh setup.sh 2>/dev/null || true

# Create systemd service file for auto-start (optional)
SERVICE_FILE="/etc/systemd/system/dns-spoofing-framework.service"
if [ "$IS_KALI" = true ] && [ "$EUID" -eq 0 ] && [ ! -f "$SERVICE_FILE" ]; then
    echo "[+] Creating systemd service file (requires root)..."
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=DNS Spoofing Simulation Framework
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/python3 -m app.main
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    echo "[+] Systemd service created at $SERVICE_FILE"
    echo "    Enable with: sudo systemctl enable dns-spoofing-framework"
    echo "    Start with:  sudo systemctl start dns-spoofing-framework"
fi

echo "======================================================================"
echo "  ✅ Setup complete! You can now run the framework on Kali Linux:"
echo "     sudo ./run.sh          # Live monitoring (requires root)"
echo "     ./demo.sh              # Demo mode (no root needed)"
echo ""
echo "  Optional systemd service:"
echo "     sudo systemctl enable dns-spoofing-framework"
echo "     sudo systemctl start dns-spoofing-framework"
echo "======================================================================"
