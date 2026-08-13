# 🛡️ DNS Spoofing Detection & Threat Intelligence Framework

![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-red?logo=wireshark)
![SQLite WAL](https://img.shields.io/badge/SQLite-WAL--Optimized-lightgrey?logo=sqlite)
![MITRE ATT%26CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1557.006%20%7C%20T1568.002-orange)
![License](https://img.shields.io/badge/License-MIT-green)

A high-performance, **cybersecurity defensive monitoring & threat intelligence platform** designed for detecting DNS spoofing, cache poisoning, fast-flux botnet networks, and Domain Generation Algorithms (DGA) in realtime or offline PCAP packet captures.

Created by **[Aniket Chand](https://github.com/ANIKETCHAND)**.

---

## 🌟 Key Features & Toolsets

### 1. 📡 Passive Real-Time Packet Sniffer
- Powered by **Scapy** with promiscuous raw socket capture on **Kali Linux** (`eth0`, `wlan0`, `lo`, `any`) and **Windows**.
- Non-blocking batch queueing engine capable of processing high-volume packet streams without frame loss.

### 2. 🎯 MITRE ATT&CK Threat Mapping
Automated threat mapping for all detected findings:
- **T1557.006**: *Adversary-in-the-Middle (DNS Spoofing / Cache Poisoning)*
- **T1568.002**: *Dynamic Resolution (Fast-Flux Botnet Networks)*
- **T1071.004**: *Application Layer Protocol (DNS Tunneling & DGA)*

### 3. 🧬 Multi-Rule Anomaly & Entropy Engine
Evaluates every DNS response against 8 detection rules:
- **Unexpected IP Response**: Detects responses deviating from trusted domain baselines.
- **Untrusted Resolver / DNS Server**: Flags unauthorized DNS server IPs.
- **TTL Anomaly Check**: Identifies abnormally low or high TTLs used in cache poisoning attacks.
- **Shannon Entropy DGA Detection**: Calculates label Shannon entropy to detect DGA/C2 tunneling:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- **Sub-30s Fast-Flux Indicator**: Detects rapid IP fluxing with short TTLs.

### 4. 📁 Forensic PCAP / PCAPNG Inspection
- Drag-and-drop offline packet capture parser.
- Extracts DNS query types (`A`, `AAAA`, `CNAME`), response IPs, TTLs, and generates risk assessments.

### 5. 📄 Threat Intelligence Report Generator
- **Executive HTML Summary**: Printable forensic incident report formatted with threat metrics and containment steps.
- **CSV Incident Log**: Offline raw data dump for evidence preservation.
- **JSON SIEM Feed**: Formatted for SIEM ingestion (Splunk, Elastic, Sentinel).

### 🎨 3D Technical Aesthetics & UI
- **Three.js WebGL 3D Canvas**: Live rotating 3D wireframe cyber sphere with an inner core.
- **CSS 3D Glassmorphic Cards**: Perspective transforms (`perspective(1000px)`), neon cyan/blue lighting, and custom pulse status indicators.
- **Single-Page Application (SPA)**: Tab switching across Dashboard, DNS Events, Security Alerts, PCAP Analysis, and Settings.

---

## 🛠️ Architecture & Technology Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Backend Engine** | Python 3.10+ / FastAPI | Async API routing, dependency injection & automated schema validation |
| **Packet Sniffer** | Scapy / Sockets | Multithreaded passive DNS packet parser & interface enumerator |
| **Database** | SQLite 3 (WAL Mode) | Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) with 64MB memory page cache |
| **Frontend UI** | HTML5 / Vanilla JS / CSS3 | Glassmorphic 3D design system with zero heavy dependencies |
| **3D & Visuals** | Three.js / Chart.js | WebGL interactive 3D logo rendering & realtime chart distribution |
| **Testing** | Pytest | 17 automated unit and integration tests |

---

## 📂 Repository Structure

```
dns-spoofing-framework/
├── app/                    # Backend Core Application
│   ├── api/                # FastAPI REST Endpoints & Report Exporters
│   ├── config.py           # Configuration & Environment Settings
│   ├── database/           # SQLite Database Models & WAL Connection Engine
│   ├── detection/          # Multi-Rule Engine, Shannon Entropy & Risk Scoring
│   ├── dns/                # Scapy Live Sniffer, Parser & Demo Simulator
│   └── utils/              # Thread-Safe Logging & Utilities
├── config/                 # Domain Baseline JSON Configurations
├── frontend/               # Frontend Assets & Web Templates
│   ├── static/
│   │   ├── css/style.css   # 3D Glassmorphism & Cyber Styling
│   │   ├── js/dashboard.js # SPA Router, Three.js 3D Canvas & Chart.js
│   │   └── images/         # 3D Technical Logos & Graphics
│   └── templates/          # Jinja2 HTML Templates (index.html, events.html)
├── tests/                  # Pytest Automated Test Suite
├── setup.sh                # Linux / Kali Linux Automated Installer
├── run.sh                  # Linux / Kali Linux Root Launcher
├── demo.sh                 # Linux Demo Script Launcher
├── requirements.txt        # Python Package Dependencies
└── README.md               # Project Documentation
```

---

## ⚙️ Installation & Setup

### 🐉 Kali Linux / Debian / Ubuntu (Automated)

```bash
# 1. Clone the repository
git clone https://github.com/ANIKETCHAND/dns-spoofing-framework.git
cd dns-spoofing-framework

# 2. Run the automated setup script
chmod +x setup.sh run.sh demo.sh
sudo ./setup.sh

# 3. Launch with root privileges (required for Scapy raw socket capture)
sudo ./run.sh
```

### 💻 Windows Setup

```powershell
# 1. Clone the repository
git clone https://github.com/ANIKETCHAND/dns-spoofing-framework.git
cd dns-spoofing-framework

# 2. Create virtual environment & install requirements
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt pytest

# 3. Start the application
.\venv\Scripts\python -m app.main
```

Open your browser and navigate to: **`http://localhost:8000`**

---

## 🌐 Production Deployment Options

### 🐳 Option 1: Docker & Docker Compose (Recommended)

Run the application inside an isolated Docker container with zero dependency management:

```bash
# 1. Build and launch with Docker Compose
docker-compose up -d --build

# 2. View running application logs
docker-compose logs -f
```

### ☁️ Option 2: 1-Click Free Cloud Deployment on Render.com

1. Go to **[Render.com](https://render.com/)** and sign in with GitHub.
2. Click **New +** -> **Web Service**.
3. Select your repository: `ANIKETCHAND/dns-spoofing-framework`.
4. Render will automatically detect `render.yaml` and configure:
   - **Environment**: Python 3.11
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Click **Create Web Service**. Your live URL will be active in ~2 minutes!

### 🚅 Option 3: Railway.app / Hugging Face Spaces

1. Connect your repository `ANIKETCHAND/dns-spoofing-framework` to **[Railway.app](https://railway.app/)**.
2. Railway will automatically pick up the `Procfile` and deploy your live web service.

---

## 🧪 Automated Testing

Run the test suite to verify detection rules, API endpoints, and live monitor status:

```bash
python -m pytest tests/ -v
```

---

## 🚀 How to Push This Project to Your GitHub

Follow these simple steps in your terminal to publish this framework to your GitHub repository:

```bash
# 1. Initialize Git in the project directory
git init

# 2. Add remote repository URL
git remote add origin https://github.com/ANIKETCHAND/dns-spoofing-framework.git

# 3. Stage all project files
git add .

# 4. Commit changes with a descriptive message
git commit -m "Initial commit: Defense-grade DNS Spoofing Framework with 3D UI, MITRE ATT&CK mapping & Shannon entropy detection"

# 5. Push to GitHub main branch
git branch -M main
git push -u origin main
```

---

## 📜 Ethical & Legal Disclaimer

This framework is created **ONLY** for authorized educational research, security testing, and Blue Team defensive analysis in isolated lab environments. Do not execute packet sniffing or security testing against networks without explicit permission.

---

## 👤 Author

**Aniket Chand**
- GitHub: [@ANIKETCHAND](https://github.com/ANIKETCHAND)
- Repository: [ANIKETCHAND/dns-spoofing-framework](https://github.com/ANIKETCHAND/dns-spoofing-framework)