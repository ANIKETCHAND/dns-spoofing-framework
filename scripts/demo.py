#!/usr/bin/env python3
"""
Demo script for DNS Spoofing Simulation Framework.

This script runs a complete demo of the DNS spoofing detection framework
in a single process with simulated DNS traffic.
"""
import sys
import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

# Add project root directory to path cleanly across all operating systems
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.dns.simulator import DNSSimulator
from app.database.database import init_database, get_db_session
from app.detection.engine import DetectionEngine
from app.dns.parser import extract_dns_from_pcap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Run the demo sequence."""
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    print("\n" + "="*70)
    print("  🌐 DNS Spoofing Simulation Framework - Demo Mode")
    print("="*70 + "\n")

    # Initialize database
    print("Initializing database...")
    init_database()
    logger.info("Database initialized")

    # Create simulator
    print("\nStarting simulator...")
    simulator = DNSSimulator()

    # Option 1: Run demo sequence
    print("\n" + "-"*70)
    print("Option 1: Running Demo Sequence")
    print("-"*70)
    try:
        results = simulator.run_demo_sequence(iterations=2, delay=0.1)
        print(f"\nDemo complete: {len(results)} simulation events generated")
    except Exception as e:
        logger.error(f"Demo sequence error: {e}")
        print(f"Error: {e}")

    # Option 2: Run PCAP analysis
    print("\n" + "-"*70)
    print("Option 2: PCAP Analysis Check")
    print("-"*70)
    pcap_path = PROJECT_ROOT / "demo" / "pcap" / "sample.pcap"
    if pcap_path.exists():
        try:
            records = extract_dns_from_pcap(str(pcap_path))
            print(f"PCAP analysis: {len(records)} DNS records extracted from {pcap_path}")
        except Exception as e:
            print(f"PCAP analysis error: {e}")
    else:
        print(f"Sample PCAP file not found at {pcap_path} (Skipping PCAP demo)")

    # Option 3: Interactive demo
    print("\n" + "-"*70)
    print("Option 3: Interactive Demo")
    print("-"*70)
    print("Available lab domains:", list(simulator.get_lab_domains().keys()))

    try:
        # Prompt for non-interactive fallback if stdin is not a tty
        if not sys.stdin.isatty():
            domain = "example.test"
            print(f"Non-interactive terminal detected. Using default lab domain: '{domain}'")
        else:
            domain = input("Enter a domain name (press Enter for 'example.test'): ").strip()
            if not domain:
                domain = "example.test"

        if not simulator.is_lab_domain(domain):
            print(f"⚠️  Domain '{domain}' is not configured in lab_domains.json")
            print(f"   Configured domains: {list(simulator.get_lab_domains().keys())}")
            return

        # Simulate normal query
        normal = simulator.simulate_normal_query(domain)
        print(f"\n✅ Normal response for {domain}:")
        print(f"   Expected IP: {normal.get('expected_ip', 'N/A')}")
        print(f"   Received IP: {normal.get('response_ip', 'N/A')}")
        print(f"   Risk Score: {normal.get('risk_score', 'N/A')}")
        print(f"   Status: {normal.get('status', 'N/A')}")

        # Simulate spoofed query
        spoofed = simulator.simulate_spoofed_query(domain)
        print(f"\n🔴 Spoofed response for {domain}:")
        print(f"   Expected IP: {spoofed.get('expected_ip', 'N/A')}")
        print(f"   Received IP: {spoofed.get('response_ip', 'N/A')}")
        print(f"   Risk Score: {spoofed.get('risk_score', 'N/A')}")
        print(f"   Status: {spoofed.get('status', 'N/A')}")

        # Run detection engine check
        with get_db_session() as db:
            engine = DetectionEngine(db_session=db)
            event = engine.analyze_event_data(
                domain=domain,
                source_ip="192.168.56.10",
                query_type="A",
                response_ip=spoofed.get("response_ip"),
                ttl=spoofed.get("ttl"),
                dns_server=spoofed.get("dns_server"),
                is_simulation=True
            )
            print(f"\n📊 Detection Result:")
            print(f"   Risk Score: {event.risk_score}")
            print(f"   Severity: {event.severity}")

    except KeyboardInterrupt:
        print("\nDemo cancelled by user.")
    except Exception as e:
        logger.error(f"Interactive demo error: {e}")

    print("\n" + "="*70)
    print("  Demo Complete! 🎉")
    print("="*70 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())