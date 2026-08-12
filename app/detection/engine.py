"""
Main Detection Engine for DNS Spoofing Framework.
Orchestrates rules, scoring, and alert generation.
"""
import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

from app.database.models import DNSEvent, Alert, SeverityLevel, EventStatus, TrustedDomain
from app.database.database import get_db_session
from app.detection.rules import DNSDetectionRules, DetectionFinding
from app.detection.scoring import RiskScorer, RiskAssessment, SeverityLevel as ScoringSeverity

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Main detection engine that processes DNS events and generates alerts.
    """

    def __init__(self, db_session=None):
        self.db = db_session
        self.rules = DNSDetectionRules(db_session)
        self.scorer = RiskScorer()

    def process_dns_event(self, event: DNSEvent) -> RiskAssessment:
        """
        Process a DNS event through all detection rules and generate assessment.

        Args:
            event: DNSEvent object with query/response data

        Returns:
            RiskAssessment with score, severity, and recommendations
        """
        # Run all detection rules
        findings = self.rules.run_all_rules(event)

        # Calculate risk score and severity
        assessment = self.scorer.assess(findings)

        # Update event with results
        event.risk_score = assessment.risk_score
        event.severity = assessment.severity.value
        event.detection_reasons = json.dumps([
            {
                "rule": f.rule_name,
                "triggered": f.triggered,
                "severity": f.severity,
                "score": f.score_contribution,
                "description": f.description,
                "details": f.details
            }
            for f in findings
        ])

        # Determine event status
        if assessment.severity in (ScoringSeverity.HIGH, ScoringSeverity.CRITICAL):
            event.status = EventStatus.SPOOFED.value
        elif assessment.severity == ScoringSeverity.MEDIUM:
            event.status = EventStatus.SUSPICIOUS.value
        else:
            event.status = EventStatus.NORMAL.value

        # Generate alert if suspicious
        if assessment.severity in (ScoringSeverity.MEDIUM, ScoringSeverity.HIGH, ScoringSeverity.CRITICAL):
            self._create_alert(event, assessment)

        logger.info(
            f"Processed DNS event: domain={event.domain}, "
            f"risk={assessment.risk_score}, severity={assessment.severity.value}"
        )

        return assessment

    def _create_alert(self, event: DNSEvent, assessment: RiskAssessment) -> Alert:
        """Create an alert for suspicious DNS activity."""
        # Create alert title based on top triggered rule
        triggered_findings = [f for f in assessment.triggered_rules]
        top_finding = max(triggered_findings, key=lambda f: f.score_contribution) if triggered_findings else None

        if top_finding:
            title = f"DNS Spoofing Detected: {top_finding.rule_name.replace('_', ' ').title()}"
        else:
            title = "DNS Anomaly Detected"

        alert = Alert(
            event_id=event.id,
            severity=assessment.severity.value,
            title=title,
            description=assessment.summary,
        )

        self.db.add(alert)
        self.db.flush()  # Get the alert ID

        logger.warning(f"Alert created: {alert.title} (Severity: {alert.severity})")
        return alert

    def analyze_event_data(
        self,
        domain: str,
        source_ip: str,
        query_type: str,
        response_ip: str,
        ttl: Optional[int] = None,
        dns_server: Optional[str] = None,
        is_simulation: bool = False
    ) -> DNSEvent:
        """
        Create and analyze a DNS event from raw data.

        This is the main entry point for external data (PCAP, live capture, simulation).
        """
        with get_db_session() as db:
            # Create event
            event = DNSEvent(
                source_ip=source_ip,
                domain=domain,
                query_type=query_type,
                response_ip=response_ip,
                ttl=ttl,
                dns_server=dns_server,
                is_simulation=is_simulation
            )

            # Look up expected IP from trusted domains
            trusted = db.query(TrustedDomain).filter(
                TrustedDomain.domain == domain,
                TrustedDomain.is_active == True
            ).first()
            if trusted:
                event.expected_ip = trusted.expected_ip

            db.add(event)
            db.flush()  # Get event ID

            # Process through detection engine
            self.db = db  # Temporarily set db for rules
            assessment = self.process_dns_event(event)
            self.db = None  # Clear db reference

            db.commit()
            db.refresh(event)

            return event

    def get_recent_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Alert]:
        """Get recent alerts with optional severity filter."""
        with get_db_session() as db:
            query = db.query(Alert).order_by(Alert.timestamp.desc())
            if severity:
                query = query.filter(Alert.severity == severity)
            return query.limit(limit).all()

    def get_dns_events(
        self,
        limit: int = 100,
        domain: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        is_simulation: Optional[bool] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[DNSEvent]:
        """Get DNS events with filtering options."""
        with get_db_session() as db:
            query = db.query(DNSEvent).order_by(DNSEvent.timestamp.desc())

            if domain:
                query = query.filter(DNSEvent.domain.ilike(f"%{domain}%"))
            if severity:
                query = query.filter(DNSEvent.severity == severity)
            if status:
                query = query.filter(DNSEvent.status == status)
            if is_simulation is not None:
                query = query.filter(DNSEvent.is_simulation == is_simulation)
            if start_time:
                query = query.filter(DNSEvent.timestamp >= start_time)
            if end_time:
                query = query.filter(DNSEvent.timestamp <= end_time)

            return query.limit(limit).all()

    def get_statistics(self) -> Dict[str, Any]:
        """Get dashboard statistics (single-pass aggregated query)."""
        from sqlalchemy import func, case

        with get_db_session() as db:
            # Single SQL query for all event aggregations
            stats_row = db.query(
                func.count(DNSEvent.id).label("total"),
                func.sum(case((DNSEvent.severity.in_(["MEDIUM", "HIGH", "CRITICAL"]), 1), else_=0)).label("suspicious"),
                func.sum(case((DNSEvent.status == EventStatus.SPOOFED.value, 1), else_=0)).label("spoofed"),
                func.sum(case((DNSEvent.severity == "LOW", 1), else_=0)).label("low_cnt"),
                func.sum(case((DNSEvent.severity == "MEDIUM", 1), else_=0)).label("med_cnt"),
                func.sum(case((DNSEvent.severity == "HIGH", 1), else_=0)).label("high_cnt"),
                func.sum(case((DNSEvent.severity == "CRITICAL", 1), else_=0)).label("crit_cnt")
            ).first()

            critical_alerts = db.query(Alert).filter(Alert.severity == ScoringSeverity.CRITICAL.value).count()

            # Top domains
            top_domains = db.query(
                DNSEvent.domain,
                func.count(DNSEvent.id).label('count')
            ).group_by(DNSEvent.domain).order_by(func.count(DNSEvent.id).desc()).limit(10).all()

            total_queries = stats_row.total if stats_row and stats_row.total else 0
            suspicious_queries = stats_row.suspicious if stats_row and stats_row.suspicious else 0
            spoofed_events = stats_row.spoofed if stats_row and stats_row.spoofed else 0

            severity_dist = {
                "LOW": stats_row.low_cnt if stats_row and stats_row.low_cnt else 0,
                "MEDIUM": stats_row.med_cnt if stats_row and stats_row.med_cnt else 0,
                "HIGH": stats_row.high_cnt if stats_row and stats_row.high_cnt else 0,
                "CRITICAL": stats_row.crit_cnt if stats_row and stats_row.crit_cnt else 0,
            }

            return {
                "total_queries": total_queries,
                "suspicious_queries": suspicious_queries,
                "spoofed_events": spoofed_events,
                "critical_alerts": critical_alerts,
                "severity_distribution": severity_dist,
                "top_domains": [{"domain": d, "count": c} for d, c in top_domains]
            }

    def get_events_over_time(self, hours: int = 24, interval_minutes: int = 60) -> List[Dict[str, Any]]:
        """Get DNS event counts over time for charts."""
        from sqlalchemy import func, text
        from datetime import timedelta

        with get_db_session() as db:
            cutoff = datetime.utcnow() - timedelta(hours=hours)

            # Use SQLite time grouping
            interval_sql = f"strftime('%Y-%m-%d %H:{interval_minutes//60:02d}:00', timestamp)"
            if interval_minutes < 60:
                interval_sql = f"strftime('%Y-%m-%d %H:%M:00', timestamp, 'start of hour', '+{interval_minutes} minutes')"

            results = db.execute(text(f"""
                SELECT
                    strftime('%Y-%m-%d %H:00:00', timestamp) as time_bucket,
                    COUNT(*) as total,
                    SUM(CASE WHEN severity IN ('MEDIUM', 'HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as suspicious
                FROM dns_events
                WHERE timestamp >= :cutoff
                GROUP BY time_bucket
                ORDER BY time_bucket
            """), {"cutoff": cutoff}).fetchall()

            return [
                {
                    "time": row.time_bucket,
                    "total": row.total,
                    "suspicious": row.suspicious or 0
                }
                for row in results
            ]


# Convenience functions
def analyze_dns_event(
    domain: str,
    source_ip: str,
    query_type: str,
    response_ip: str,
    ttl: Optional[int] = None,
    dns_server: Optional[str] = None,
    is_simulation: bool = False
) -> DNSEvent:
    """Quick analysis function for external use."""
    engine = DetectionEngine()
    return engine.analyze_event_data(
        domain=domain,
        source_ip=source_ip,
        query_type=query_type,
        response_ip=response_ip,
        ttl=ttl,
        dns_server=dns_server,
        is_simulation=is_simulation
    )