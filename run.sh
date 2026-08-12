#!/usr/bin/env bash
# ==============================================================================
# Launcher script for DNS Spoofing Simulation Framework on Kali Linux
# ==============================================================================
set -e

# Change directory to project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# Detect OS for better messages
if [ -f /etc/os-release ]; then
    . /etc/os-release
    IS_KALI=false
    if [[ "$ID" == "kali" ]] || [[ "$ID" == "debian" ]] || [[ "$ID" == "ubuntu" ]]; then
        IS_KALI=true
    fi
fi

if [ ! -d "venv" ]; then
    echo "[!] Virtual environment not found. Running setup.sh first..."
    ./setup.sh
fi

# Check for root/sudo privileges (recommended for Scapy raw socket packet sniffing)
HAS_ROOT=false
if [ "$EUID" -eq 0 ]; then
    HAS_ROOT=true
    echo "[+] Running as root - live packet capture enabled"
else
    echo "======================================================================"
    echo "⚠️  NOTE: Raw packet sniffing (Scapy) on network interfaces requires root."
    echo "   Running without root will work for simulation mode, but live traffic"
    echo "   monitoring on eth0/wlan0/ens* interfaces requires root privileges."
    echo "   Consider running with: sudo ./run.sh"
    echo "======================================================================"
    echo ""
fi

# Check if Scapy can access interfaces
echo "[+] Checking Scapy interface access..."
./venv/bin/python3 -c "
try:
    from scapy.all import conf, get_if_list
    conf.verb = 0
    interfaces = get_if_list()
    print(f'[+] Available interfaces: {interfaces}')
except Exception as e:
    print(f'[!] Interface check failed: {e}')
" 2>/dev/null

# Check libpcap
if [ "$IS_KALI" = true ] && [ "$HAS_ROOT" = false ]; then
    echo "[i] Tip: On Kali Linux, you can also run without full root by using:"
    echo "     sudo setcap cap_net_raw,cap_net_admin=eip \$(which python3)"
    echo "     (Then run ./run.sh without sudo)"
    echo ""
fi

echo "======================================================================"
echo "🚀 Starting DNS Spoofing Simulation Framework Server..."
echo "   Dashboard URL: http://127.0.0.1:8000"
if [ "$HAS_ROOT" = true ]; then
    echo "   Mode: LIVE MONITORING (root)"
else:
    echo "   Mode: SIMULATION ONLY (no root)"
fi
echo "======================================================================"

./venv/bin/python3 -m app.main
