"""
Unit and API integration tests for DNS Traffic Monitor and Interface controls.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.dns.monitor import get_available_interfaces, get_monitor_status, DNSMonitor
from app.database.database import init_database

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    """Initialize database for tests."""
    init_database()


def test_interface_discovery():
    """Test network interface enumeration."""
    ifaces = get_available_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0


def test_monitor_status():
    """Test getting monitor status."""
    status = get_monitor_status()
    assert "running" in status
    assert "available_interfaces" in status
    assert isinstance(status["available_interfaces"], list)


def test_monitor_api_endpoints():
    """Test monitor API routes."""
    # Interfaces endpoint
    res = client.get("/api/monitor/interfaces")
    assert res.status_code == 200
    assert "interfaces" in res.json()

    # Status endpoint
    res = client.get("/api/monitor/status")
    assert res.status_code == 200
    assert "running" in res.json()

    # Start endpoint
    res = client.post("/api/monitor/start")
    assert res.status_code == 200

    # Stop endpoint
    res = client.post("/api/monitor/stop")
    assert res.status_code == 200
