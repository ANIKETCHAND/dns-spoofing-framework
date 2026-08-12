"""
Integration tests for FastAPI endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.database import init_database

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    """Initialize database for tests."""
    init_database()


def test_health_check():
    """Test health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_dashboard_stats():
    """Test dashboard statistics endpoint."""
    response = client.get("/api/dashboard-stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_queries" in data
    assert "suspicious_queries" in data
    assert "spoofed_events" in data
    assert "critical_alerts" in data


def test_get_dns_events():
    """Test getting DNS events list."""
    response = client.get("/api/dns-events?limit=10")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_simulation_batch():
    """Test batch simulation endpoint."""
    response = client.post("/api/simulate-batch?count=4")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["count"] > 0


def test_clear_simulation_data():
    """Test clearing simulation data endpoint."""
    response = client.delete("/api/dns-events/clear-simulation")
    assert response.status_code == 200
    assert "Deleted" in response.json()["message"]


def test_html_page_routes():
    """Test HTML rendering page routes."""
    for path in ["/", "/dashboard", "/events", "/alerts", "/pcap", "/settings"]:
        response = client.get(path)
        assert response.status_code == 200
        assert "<html" in response.text.lower()
