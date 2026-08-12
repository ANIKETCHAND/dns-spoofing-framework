"""
Unit tests for DNS Spoofing Detection Engine and Rules.
"""
import pytest
from app.database.models import DNSEvent, TrustedDomain
from app.database.database import get_db_session, init_database
from app.detection.engine import DetectionEngine
from app.detection.rules import DNSDetectionRules
from app.detection.scoring import RiskScorer


@pytest.fixture(autouse=True)
def setup_db():
    """Initialize database before tests."""
    init_database()
    with get_db_session() as db:
        # Add trusted domain baseline
        trusted = db.query(TrustedDomain).filter(TrustedDomain.domain == "example.test").first()
        if not trusted:
            trusted = TrustedDomain(
                domain="example.test",
                expected_ip="192.168.56.20",
                expected_ttl_min=300,
                expected_ttl_max=86400,
                is_active=True
            )
            db.add(trusted)
            db.commit()


def test_unexpected_ip_rule():
    """Test detection rule when response IP differs from trusted baseline."""
    with get_db_session() as db:
        rules = DNSDetectionRules(db_session=db)
        event = DNSEvent(
            domain="example.test",
            source_ip="192.168.56.10",
            response_ip="192.168.56.99",  # Spoofed IP!
            ttl=3600
        )
        finding = rules.rule_unexpected_ip(event)
        assert finding.triggered is True
        assert finding.severity == "CRITICAL"
        assert finding.score_contribution > 0


def test_normal_ip_rule():
    """Test rule when response matches trusted baseline."""
    with get_db_session() as db:
        rules = DNSDetectionRules(db_session=db)
        event = DNSEvent(
            domain="example.test",
            source_ip="192.168.56.10",
            response_ip="192.168.56.20",  # Legitimate IP
            ttl=3600
        )
        finding = rules.rule_unexpected_ip(event)
        assert finding.triggered is False
        assert finding.score_contribution == 0


def test_ttl_anomaly_rule():
    """Test detection rule for suspiciously low TTL."""
    with get_db_session() as db:
        rules = DNSDetectionRules(db_session=db)
        event = DNSEvent(
            domain="example.test",
            source_ip="192.168.56.10",
            response_ip="192.168.56.20",
            ttl=10  # Suspiciously low (< 300s)
        )
        finding = rules.rule_ttl_anomaly(event)
        assert finding.triggered is True
        assert finding.severity in ("MEDIUM", "HIGH")


def test_detection_engine_end_to_end():
    """Test processing an event through the complete detection engine."""
    with get_db_session() as db:
        engine = DetectionEngine(db_session=db)
        event = engine.analyze_event_data(
            domain="example.test",
            source_ip="192.168.56.10",
            query_type="A",
            response_ip="192.168.56.99",  # Spoofed IP
            ttl=30,
            is_simulation=True
        )

        assert event.id is not None
        assert event.risk_score > 0
        assert event.severity in ("MEDIUM", "HIGH", "CRITICAL")
        assert event.status in ("SUSPICIOUS", "SPOOFED")
