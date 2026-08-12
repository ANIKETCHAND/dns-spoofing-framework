"""
Configuration management for DNS Spoofing Framework.
"""
import os
import platform
from pathlib import Path
from typing import List

class Settings:
    """Application settings."""

    # Base directory
    BASE_DIR = Path(__file__).resolve().parent.parent

    # Database
    DB_PATH = os.environ.get("DNS_FRAMEWORK_DB", str(BASE_DIR / "data" / "dns_framework.db"))

    # Config
    CONFIG_DIR = BASE_DIR / "config"
    LAB_DOMAINS_FILE = CONFIG_DIR / "lab_domains.json"

    # Frontend
    FRONTEND_DIR = BASE_DIR / "frontend"

    # Server
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", 8000))
    DEBUG = os.environ.get("DEBUG", "true").lower() == "true"

    # Security
    SECRET_KEY = os.environ.get("SECRET_KEY", "lab-mode-not-for-Production-use-only")

    # Simulation settings
    SIMULATION_MODE = True
    MAX_SIMULATION_EVENTS = 1000

    # PCAP settings
    MAX_PCAP_SIZE_MB = 100

    # Lab mode safety
    LAB_MODE = True
    ALLOWED_NETWORKS = ["192.168.56.0/24", "10.0.0.0/24", "172.16.0.0/12"]

    # Performance settings (can be tuned via env vars)
    DB_WAL_MODE = os.environ.get("DNS_DB_WAL_MODE", "true").lower() == "true"
    DB_CACHE_SIZE_MB = int(os.environ.get("DNS_DB_CACHE_SIZE_MB", "64"))
    PCAP_BATCH_SIZE = int(os.environ.get("DNS_PCAP_BATCH_SIZE", "1000"))
    MONITOR_BATCH_SIZE = int(os.environ.get("DNS_MONITOR_BATCH_SIZE", "100"))
    CACHE_TTL_SECONDS = int(os.environ.get("DNS_CACHE_TTL_SECONDS", "5"))

    # Kali Linux / Linux specific
    DEFAULT_INTERFACE = os.environ.get("DNS_DEFAULT_INTERFACE", "")
    PROMISCUOUS_MODE = os.environ.get("DNS_PROMISCUOUS", "true").lower() == "true"

    @classmethod
    def print_config(cls) -> None:
        """Print configuration for startup."""
        import sys
        if hasattr(sys.stdout, 'reconfigure'):
            try:
                sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            except Exception:
                pass

        is_kali = platform.system() == "Linux" and os.path.exists("/etc/kali-release")
        is_linux = platform.system() == "Linux"

        print(f"\n{'='*60}")
        print("DNS Spoofing Framework Configuration")
        print(f"{'='*60}")
        print(f"OS: {platform.system()} {platform.release()} {'(Kali)' if is_kali else ''}")
        print(f"Python: {platform.python_version()}")
        print(f"LAB MODE: {'ACTIVE [OK]' if cls.LAB_MODE else 'INACTIVE [X]'}")
        print(f"Database: {cls.DB_PATH}")
        print(f"DB WAL Mode: {cls.DB_WAL_MODE}")
        print(f"DB Cache: {cls.DB_CACHE_SIZE_MB}MB")
        print(f"Lab Config: {cls.LAB_DOMAINS_FILE}")
        print(f"Host: {cls.HOST}:{cls.PORT}")
        print(f"Debug: {cls.DEBUG}")
        print(f"Default Interface: {cls.DEFAULT_INTERFACE or 'auto-detect'}")
        print(f"Promiscuous Mode: {cls.PROMISCUOUS_MODE}")
        print(f"Monitor Batch Size: {cls.MONITOR_BATCH_SIZE}")
        print(f"PCAP Batch Size: {cls.PCAP_BATCH_SIZE}")
        print(f"Cache TTL: {cls.CACHE_TTL_SECONDS}s")
        print(f"{'='*60}\n")


settings = Settings()