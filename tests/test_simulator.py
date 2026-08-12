"""
Unit tests for DNS Spoofing Simulator.
"""
import pytest
from app.dns.simulator import DNSSimulator
from app.database.database import init_database


@pytest.fixture(autouse=True)
def setup_database():
    """Initialize database for tests."""
    init_database()


def test_simulator_load_domains():
    """Test simulator loads lab domain configurations properly."""
    simulator = DNSSimulator()
    domains = simulator.get_lab_domains()
    assert len(domains) > 0
    assert "example.test" in domains


def test_simulate_normal_query():
    """Test generating a normal query response."""
    simulator = DNSSimulator()
    result = simulator.simulate_normal_query("example.test")
    assert result is not None
    assert result["domain"] == "example.test"
    assert result["simulation_type"] == "NORMAL"
    assert result["is_simulation"] is True


def test_simulate_spoofed_query():
    """Test generating a spoofed query response."""
    simulator = DNSSimulator()
    result = simulator.simulate_spoofed_query("example.test")
    assert result is not None
    assert result["domain"] == "example.test"
    assert result["simulation_type"] == "SPOOFED"
    assert result["risk_score"] > 0


def test_demo_sequence():
    """Test running a demo sequence."""
    simulator = DNSSimulator()
    results = simulator.run_demo_sequence(iterations=1, delay=0.01)
    assert len(results) > 0
