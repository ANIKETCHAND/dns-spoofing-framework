"""
DNS Spoofing Simulator - SAFE LAB MODE ONLY.
Generates controlled fake DNS responses for configured lab domains only.
"""
import json
import logging
import random
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.database.models import SimulationEvent, TrustedDomain
from app.database.database import get_db_session
from app.detection.engine import analyze_dns_event

logger = logging.getLogger(__name__)

# LAB MODE INDICATOR - MUST BE VISIBLE IN ALL OUTPUTS
LAB_MODE_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ⚠️  LAB MODE ACTIVE - DNS SPOOFING SIMULATOR  ⚠️         ║
║                                                                              ║
║  This simulator ONLY works with domains configured in config/lab_domains.json║
║  It generates SIMULATION DATA for educational purposes only.                 ║
║  NO REAL NETWORK ATTACKS ARE PERFORMED.                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

@dataclass
class LabDomainConfig:
    """Configuration for a lab domain."""
    domain: str
    legitimate_ip: str
    simulation_ip: str


class DNSSimulator:
    """
    Safe DNS Spoofing Simulator for lab environments.

    SAFETY FEATURES:
    - Only simulates domains explicitly configured in lab_domains.json
    - Clearly marks all generated data as SIMULATION
    - No actual network packet injection
    - No ARP spoofing, no DNS cache poisoning on real networks
    - Designed for VirtualBox Host-Only/Internal networks only
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config()
        self.lab_domains: Dict[str, LabDomainConfig] = {}
        self.is_running = False
        self.simulation_count = 0
        self._load_config()

        # Print lab mode banner on initialization
        import sys
        if hasattr(sys.stdout, 'reconfigure'):
            try:
                sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            except Exception:
                pass
        try:
            print(LAB_MODE_BANNER)
        except UnicodeEncodeError:
            print("[LAB MODE ACTIVE - DNS SPOOFING SIMULATOR]")
        logger.warning("LAB MODE ACTIVE - DNS Spoofing Simulator initialized")

    def _find_config(self) -> str:
        """Find the lab configuration file."""
        # Check multiple possible locations
        possible_paths = [
            Path("config/lab_domains.json"),
            Path("../config/lab_domains.json"),
            Path("../../config/lab_domains.json"),
            Path(__file__).parent.parent.parent / "config" / "lab_domains.json",
        ]

        for path in possible_paths:
            if path.exists():
                return str(path)

        # Return default path even if not found (will error on load)
        return "config/lab_domains.json"

    def _load_config(self) -> None:
        """Load lab domain configuration from JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)

            for domain, data in config.items():
                self.lab_domains[domain] = LabDomainConfig(
                    domain=domain,
                    legitimate_ip=data.get("legitimate_ip", ""),
                    simulation_ip=data.get("simulation_ip", "")
                )

            logger.info(f"Loaded {len(self.lab_domains)} lab domains from {self.config_path}")
            for domain, config in self.lab_domains.items():
                logger.info(f"  {domain}: legitimate={config.legitimate_ip}, simulation={config.simulation_ip}")

        except FileNotFoundError:
            logger.error(f"Lab configuration not found: {self.config_path}")
            logger.error("Create config/lab_domains.json with your lab domains")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in lab configuration: {e}")
            raise

    def get_lab_domains(self) -> Dict[str, LabDomainConfig]:
        """Get all configured lab domains."""
        return self.lab_domains.copy()

    def is_lab_domain(self, domain: str) -> bool:
        """Check if a domain is configured for simulation."""
        return domain in self.lab_domains

    def simulate_normal_query(
        self,
        domain: str,
        source_ip: str = "192.168.56.10",
        query_type: str = "A",
        dns_server: str = "192.168.56.2",
        ttl: int = 3600
    ) -> Optional[Dict[str, Any]]:
        """
        Simulate a NORMAL DNS response (legitimate IP).

        Args:
            domain: Domain to query (must be in lab_domains)
            source_ip: Source IP of the query
            query_type: DNS query type
            dns_server: DNS server responding
            ttl: TTL value

        Returns:
            Dictionary with event data or None if domain not in lab config
        """
        if not self.is_lab_domain(domain):
            logger.warning(f"Domain {domain} not in lab configuration - skipping simulation")
            return None

        config = self.lab_domains[domain]

        # Analyze through detection engine
        event = analyze_dns_event(
            domain=domain,
            source_ip=source_ip,
            query_type=query_type,
            response_ip=config.legitimate_ip,
            ttl=ttl,
            dns_server=dns_server,
            is_simulation=True
        )

        # Record simulation event
        self._record_simulation(domain, config.legitimate_ip, config.simulation_ip, "normal")

        return {
            "domain": domain,
            "source_ip": source_ip,
            "query_type": query_type,
            "response_ip": config.legitimate_ip,
            "expected_ip": config.legitimate_ip,
            "ttl": ttl,
            "dns_server": dns_server,
            "risk_score": event.risk_score,
            "severity": event.severity,
            "status": event.status,
            "is_simulation": True,
            "simulation_type": "NORMAL"
        }

    def simulate_spoofed_query(
        self,
        domain: str,
        source_ip: str = "192.168.56.10",
        query_type: str = "A",
        dns_server: str = "192.168.56.99",  # Different DNS server!
        ttl: int = 60  # Suspiciously low TTL
    ) -> Optional[Dict[str, Any]]:
        """
        Simulate a SPOOFED DNS response (simulation IP).

        Args:
            domain: Domain to query (must be in lab_domains)
            source_ip: Source IP of the query
            query_type: DNS query type
            dns_server: DNS server responding (often different from legitimate)
            ttl: TTL value (often anomalous)

        Returns:
            Dictionary with event data or None if domain not in lab config
        """
        if not self.is_lab_domain(domain):
            logger.warning(f"Domain {domain} not in lab configuration - skipping simulation")
            return None

        config = self.lab_domains[domain]

        # Analyze through detection engine
        event = analyze_dns_event(
            domain=domain,
            source_ip=source_ip,
            query_type=query_type,
            response_ip=config.simulation_ip,
            ttl=ttl,
            dns_server=dns_server,
            is_simulation=True
        )

        # Record simulation event
        self._record_simulation(domain, config.legitimate_ip, config.simulation_ip, "spoofed")

        return {
            "domain": domain,
            "source_ip": source_ip,
            "query_type": query_type,
            "response_ip": config.simulation_ip,
            "expected_ip": config.legitimate_ip,
            "ttl": ttl,
            "dns_server": dns_server,
            "risk_score": event.risk_score,
            "severity": event.severity,
            "status": event.status,
            "is_simulation": True,
            "simulation_type": "SPOOFED"
        }

    def _record_simulation(self, domain: str, legitimate_ip: str, simulation_ip: str, simulation_type: str) -> None:
        """Record a simulation event in the database."""
        self.simulation_count += 1

        with get_db_session() as db:
            sim_event = SimulationEvent(
                domain=domain,
                legitimate_ip=legitimate_ip,
                simulation_ip=simulation_ip,
                triggered_by=f"demo_{simulation_type}",
                notes=f"LAB MODE SIMULATION #{self.simulation_count}: {simulation_type.upper()} response for {domain}"
            )
            db.add(sim_event)

        logger.info(f"SIMULATION #{self.simulation_count}: {simulation_type.upper()} - {domain} -> {simulation_ip if simulation_type == 'spoofed' else legitimate_ip}")

    def run_demo_sequence(self, iterations: int = 5, delay: float = 1.0) -> List[Dict[str, Any]]:
        """
        Run a demonstration sequence alternating normal and spoofed responses.

        Args:
            iterations: Number of normal+spoofed pairs per domain
            delay: Delay between simulations in seconds

        Returns:
            List of all simulation results
        """
        results = []

        print("\n" + "="*70)
        print("STARTING DEMO SEQUENCE - GENERATING SIMULATION DATA")
        print("="*70)

        for i in range(iterations):
            for domain in self.lab_domains:
                # Normal response
                print(f"\n[ITERATION {i+1}/{iterations}] Simulating NORMAL response for {domain}")
                result = self.simulate_normal_query(domain)
                if result:
                    results.append(result)
                    print(f"  Result: {result['status']} (Risk: {result['risk_score']})")

                time.sleep(delay / 2)

                # Spoofed response
                print(f"[ITERATION {i+1}/{iterations}] Simulating SPOOFED response for {domain}")
                result = self.simulate_spoofed_query(domain)
                if result:
                    results.append(result)
                    print(f"  Result: {result['status']} (Risk: {result['risk_score']})")

                time.sleep(delay / 2)

        print("\n" + "="*70)
        print(f"DEMO SEQUENCE COMPLETE - Generated {len(results)} simulation events")
        print("ALL DATA MARKED AS 'SIMULATION' IN DATABASE")
        print("="*70 + "\n")

        return results

    def run_random_simulation(
        self,
        duration_seconds: int = 60,
        spoof_probability: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Run random simulation for a specified duration.

        Args:
            duration_seconds: How long to run
            spoof_probability: Probability of generating a spoofed response (0-1)

        Returns:
            List of simulation results
        """
        results = []
        start_time = time.time()
        domains = list(self.lab_domains.keys())

        print(f"\nStarting random simulation for {duration_seconds} seconds...")
        print(f"Spoof probability: {spoof_probability*100:.0f}%")

        while time.time() - start_time < duration_seconds:
            domain = random.choice(domains)

            if random.random() < spoof_probability:
                result = self.simulate_spoofed_query(domain)
            else:
                result = self.simulate_normal_query(domain)

            if result:
                results.append(result)

            # Random delay between 0.5 and 3 seconds
            time.sleep(random.uniform(0.5, 3.0))

        print(f"\nRandom simulation complete. Generated {len(results)} events.")
        return results


def create_sample_config(config_path: str = "config/lab_domains.json") -> None:
    """Create a sample lab configuration file."""
    sample_config = {
        "example.test": {
            "legitimate_ip": "192.168.56.20",
            "simulation_ip": "192.168.56.99"
        },
        "portal.test": {
            "legitimate_ip": "192.168.56.30",
            "simulation_ip": "192.168.56.100"
        },
        "internal.test": {
            "legitimate_ip": "192.168.56.40",
            "simulation_ip": "192.168.56.101"
        }
    }

    Path(config_path).parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(sample_config, f, indent=4)

    print(f"Sample configuration created at {config_path}")


# Main entry point for running simulator directly
if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if len(sys.argv) > 1 and sys.argv[1] == "create-config":
        create_sample_config()
        sys.exit(0)

    try:
        simulator = DNSSimulator()
        simulator.run_demo_sequence(iterations=3, delay=0.5)
    except FileNotFoundError:
        print("Lab configuration not found. Run with 'create-config' to create a sample.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Simulation error: {e}")
        sys.exit(1)