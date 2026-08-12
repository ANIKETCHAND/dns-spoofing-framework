"""
Database models for DNS Spoofing Simulation Framework.
Uses SQLAlchemy ORM for SQLite database operations.
"""
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, ForeignKey, Index
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class SeverityLevel(str, PyEnum):
    """Severity levels for alerts and events."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventStatus(str, PyEnum):
    """Status of DNS events."""
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    SPOOFED = "SPOOFED"
    SIMULATION = "SIMULATION"


class DNSEvent(Base):
    """Model for storing DNS query/response events."""
    __tablename__ = "dns_events"
    __table_args__ = (
        Index("idx_dns_events_domain_ts", "domain", "timestamp"),
        Index("idx_dns_events_sev_ts", "severity", "timestamp"),
        Index("idx_dns_events_status_ts", "status", "timestamp"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    domain = Column(String(255), nullable=False, index=True)
    query_type = Column(String(10), default="A")  # A, AAAA, CNAME, etc.
    response_ip = Column(String(45), nullable=True)  # Null if no response yet
    expected_ip = Column(String(45), nullable=True)  # From trusted baseline
    ttl = Column(Integer, nullable=True)
    dns_server = Column(String(45), nullable=True)  # DNS server that responded
    risk_score = Column(Float, default=0.0, nullable=False)
    severity = Column(String(20), default=SeverityLevel.LOW.value)
    status = Column(String(20), default=EventStatus.NORMAL.value)
    is_simulation = Column(Boolean, default=False, nullable=False)
    detection_reasons = Column(Text, nullable=True)  # JSON string of triggered rules
    raw_packet_info = Column(Text, nullable=True)  # For PCAP import

    # Relationship to alerts
    alerts = relationship("Alert", back_populates="dns_event", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DNSEvent(domain='{self.domain}', ip='{self.response_ip}', risk={self.risk_score})>"


class Alert(Base):
    """Model for storing security alerts."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_id = Column(Integer, ForeignKey("dns_events.id"), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    acknowledged = Column(Boolean, default=False, nullable=False)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(100), nullable=True)

    # Relationship
    dns_event = relationship("DNSEvent", back_populates="alerts")

    def __repr__(self):
        return f"<Alert(severity='{self.severity}', title='{self.title}')>"


class TrustedDomain(Base):
    """Model for storing trusted domain baseline."""
    __tablename__ = "trusted_domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    expected_ip = Column(String(45), nullable=False)
    expected_ttl_min = Column(Integer, default=300)  # Minimum expected TTL
    expected_ttl_max = Column(Integer, default=86400)  # Maximum expected TTL
    trusted_dns_servers = Column(Text, nullable=True)  # JSON list of trusted DNS server IPs
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True, nullable=False)
    notes = Column(Text, nullable=True)

    def __repr__(self):
        return f"<TrustedDomain(domain='{self.domain}', ip='{self.expected_ip}')>"


class SimulationEvent(Base):
    """Model for storing simulation events for demo mode."""
    __tablename__ = "simulation_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    domain = Column(String(255), nullable=False)
    legitimate_ip = Column(String(45), nullable=False)
    simulation_ip = Column(String(45), nullable=False)
    query_type = Column(String(10), default="A")
    triggered_by = Column(String(50), default="demo")  # demo, manual, scheduled
    notes = Column(Text, nullable=True)

    def __repr__(self):
        return f"<SimulationEvent(domain='{self.domain}', legit='{self.legitimate_ip}', sim='{self.simulation_ip}')>"