"""
DNS Spoofing Detection Rules.
Each rule checks for a specific suspicious behavior and returns a finding if triggered.
"""
import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from threading import Lock

from app.database.models import DNSEvent, TrustedDomain
from app.database.database import get_db_session


@dataclass
class DetectionFinding:
    """Result of a detection rule check."""
    rule_name: str
    triggered: bool
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    score_contribution: int  # Points added to risk score (0-100)
    description: str
    details: Dict[str, Any] = field(default_factory=dict)


class DNSDetectionRules:
    """Collection of DNS spoofing detection rules."""

    def __init__(self, db_session=None):
        self.db = db_session
        self._trusted_domain_cache: Dict[str, Optional[TrustedDomain]] = {}
        self._recent_events_cache: Dict[str, List[DNSEvent]] = {}
        self._cache_ttl_seconds = 5  # Cache TTL for trusted domains and recent events
        self._cache_timestamps: Dict[str, datetime] = {}
        self._cache_lock = Lock()  # Thread-safe cache access

    def _get_trusted_domain(self, domain: str) -> Optional[TrustedDomain]:
        """Get trusted domain configuration from memory cache or database with TTL."""
        if not self.db:
            return None

        cache_key = f"trusted_{domain}"
        with self._cache_lock:
            # Check cache with TTL
            if cache_key in self._trusted_domain_cache:
                cached_time = self._cache_timestamps.get(cache_key)
                if cached_time and (datetime.utcnow() - cached_time).total_seconds() < self._cache_ttl_seconds:
                    return self._trusted_domain_cache[cache_key]

        # Fetch from database
        trusted = self.db.query(TrustedDomain).filter(
            TrustedDomain.domain == domain,
            TrustedDomain.is_active == True
        ).first()

        with self._cache_lock:
            self._trusted_domain_cache[cache_key] = trusted
            self._cache_timestamps[cache_key] = datetime.utcnow()
        return trusted

    def _get_recent_events(self, domain: str, hours: int = 24) -> List[DNSEvent]:
        """Get recent DNS events for a domain with caching."""
        if not self.db:
            return []

        cache_key = f"events_{domain}_{hours}h"
        with self._cache_lock:
            # Check cache with TTL
            if cache_key in self._recent_events_cache:
                cached_time = self._cache_timestamps.get(cache_key)
                if cached_time and (datetime.utcnow() - cached_time).total_seconds() < self._cache_ttl_seconds:
                    return self._recent_events_cache[cache_key]

        cutoff = datetime.utcnow() - timedelta(hours=hours)
        events = self.db.query(DNSEvent).filter(
            DNSEvent.domain == domain,
            DNSEvent.timestamp >= cutoff
        ).order_by(DNSEvent.timestamp.desc()).all()

        with self._cache_lock:
            self._recent_events_cache[cache_key] = events
            self._cache_timestamps[cache_key] = datetime.utcnow()
        return events

    def clear_cache(self) -> None:
        """Clear all caches."""
        with self._cache_lock:
            self._trusted_domain_cache.clear()
            self._recent_events_cache.clear()
            self._cache_timestamps.clear()

    def rule_unexpected_ip(self, event: DNSEvent) -> DetectionFinding:
        """
        Rule 1: Response IP differs from trusted baseline.
        This is the primary indicator of DNS spoofing.
        """
        trusted = self._get_trusted_domain(event.domain)
        if not trusted or not event.response_ip:
            return DetectionFinding(
                rule_name="unexpected_ip",
                triggered=False,
                severity="LOW",
                score_contribution=0,
                description="No trusted baseline configured for this domain"
            )

        if event.response_ip != trusted.expected_ip:
            return DetectionFinding(
                rule_name="unexpected_ip",
                triggered=True,
                severity="CRITICAL",
                score_contribution=40,
                description=f"DNS response IP ({event.response_ip}) differs from trusted baseline ({trusted.expected_ip})",
                details={
                    "expected_ip": trusted.expected_ip,
                    "received_ip": event.response_ip,
                    "domain": event.domain
                }
            )

        return DetectionFinding(
            rule_name="unexpected_ip",
            triggered=False,
            severity="LOW",
            score_contribution=0,
            description="Response IP matches trusted baseline"
        )

    def rule_unexpected_dns_server(self, event: DNSEvent) -> DetectionFinding:
        """
        Rule 2: Response came from an unexpected DNS server.
        Legitimate responses should come from configured DNS servers.
        """
        trusted = self._get_trusted_domain(event.domain)
        if not trusted or not trusted.trusted_dns_servers or not event.dns_server:
            return DetectionFinding(
                rule_name="unexpected_dns_server",
                triggered=False,
                severity="LOW",
                score_contribution=0,
                description="No trusted DNS servers configured or no DNS server info"
            )

        try:
            trusted_servers = json.loads(trusted.trusted_dns_servers)
        except (json.JSONDecodeError, TypeError):
            trusted_servers = []

        if event.dns_server not in trusted_servers:
            return DetectionFinding(
                rule_name="unexpected_dns_server",
                triggered=True,
                severity="HIGH",
                score_contribution=25,
                description=f"DNS response from untrusted server: {event.dns_server}",
                details={
                    "dns_server": event.dns_server,
                    "trusted_servers": trusted_servers
                }
            )

        return DetectionFinding(
            rule_name="unexpected_dns_server",
            triggered=False,
            severity="LOW",
            score_contribution=0,
            description="DNS server is in trusted list"
        )

    def rule_ttl_anomaly(self, event: DNSEvent) -> DetectionFinding:
        """
        Rule 3: TTL value is anomalous.
        Very low TTLs can indicate spoofing attempts; very high TTLs can indicate cache poisoning.
        """
        trusted = self._get_trusted_domain(event.domain)
        if not trusted or event.ttl is None:
            return DetectionFinding(
                rule_name="ttl_anomaly",
                triggered=False,
                severity="LOW",
                score_contribution=0,
                description="No TTL baseline or no TTL in response"
            )

        ttl = event.ttl
        min_ttl = trusted.expected_ttl_min
        max_ttl = trusted.expected_ttl_max

        # Check for suspiciously low TTL (possible spoofing with short-lived records)
        if ttl < min_ttl:
            severity = "HIGH" if ttl < 60 else "MEDIUM"
            score = 20 if ttl < 60 else 15
            return DetectionFinding(
                rule_name="ttl_anomaly",
                triggered=True,
                severity=severity,
                score_contribution=score,
                description=f"Suspiciously low TTL: {ttl}s (expected min: {min_ttl}s)",
                details={"ttl": ttl, "expected_min": min_ttl, "type": "low"}
            )

        # Check for suspiciously high TTL (possible cache poisoning)
        if ttl > max_ttl:
            return DetectionFinding(
                rule_name="ttl_anomaly",
                triggered=True,
                severity="MEDIUM",
                score_contribution=15,
                description=f"Unusually high TTL: {ttl}s (expected max: {max_ttl}s)",
                details={"ttl": ttl, "expected_max": max_ttl, "type": "high"}
            )

        return DetectionFinding(
            rule_name="ttl_anomaly",
            triggered=False,
            severity="LOW",
            score_contribution=0,
            description="TTL within expected range"
        )

    def rule_repeated_suspicious_responses(self, event: DNSEvent) -> DetectionFinding:
        """
        Rule 4: Multiple suspicious responses for the same domain in recent time window.
        Repeated anomalies increase confidence of an active attack.
        """
        recent_events = self._get_recent_events(event.domain, hours=1)
        if not recent_events:
            return DetectionFinding(
                rule_name="repeated_suspicious",
                triggered=False,
                severity="LOW",
                score_contribution=0,
                description="No recent events for this domain"
            )

        # Count events with risk score > 30 in the last hour
        suspicious_count = sum(1 for e in recent_events if e.risk_score > 30 and e.id != event.id)

        if suspicious_count >= 3:
            return DetectionFinding(
                rule_name="repeated_suspicious",
                triggered=True,
                severity="CRITICAL",
                score_contribution=30,
                description=f"Multiple suspicious responses detected ({suspicious_count} in last hour)",
                details={"suspicious_count": suspicious_count, "time_window": "1 hour"}
            )
        elif suspicious_count >= 1:
            return DetectionFinding(
                rule_name="repeated_suspicious",
                triggered=True,
                severity="HIGH",
                score_contribution=15,
                description=f"Previous suspicious response detected ({suspicious_count} in last hour)",
                details={"suspicious_count": suspicious_count, "time_window": "1 hour"}
            )

        return DetectionFinding(
            rule_name="repeated_suspicious",
            triggered=False,
            severity="LOW",
            score_contribution=0,
            description="No repeated suspicious responses"
        )

    def rule_multiple_ip_changes(self, event: DNSEvent) -> DetectionFinding:
        """
        Rule 5: Multiple different IPs observed for the same domain.
        Rapid IP changes can indicate DNS spoofing or fast-flux techniques.
        """
        recent_events = self._get_recent_events(event.domain, hours=24)
        if not recent_events or not event.response_ip:
            return DetectionFinding(
                rule_name="multiple_ip_changes",
                triggered=False,
                severity="LOW",
                score_contribution=0,
                description="Insufficient data for IP change analysis"
            )

        # Collect unique IPs from recent events
        unique_ips = set()
        for e in recent_events:
            if e.response_ip:
                unique_ips.add(e.response_ip)
        unique_ips.add(event.response_ip)

        if len(unique_ips) >= 4:
            return DetectionFinding(
                rule_name="multiple_ip_changes",
                triggered=True,
                severity="CRITICAL",
                score_contribution=35,
                description=f"Rapid IP changes detected: {len(unique_ips)} different IPs in 24 hours",
                details={"unique_ips": list(unique_ips), "count": len(unique_ips)}
            )
        elif len(unique_ips) >= 2:
            # Check if one of them is the trusted IP
            trusted = self._get_trusted_domain(event.domain)
            has_trusted = trusted and trusted.expected_ip in unique_ips
            severity = "HIGH" if not has_trusted else "MEDIUM"
            score = 20 if not has_trusted else 15
            return DetectionFinding(
                rule_name="multiple_ip_changes",
                triggered=True,
                severity=severity,
                score_contribution=score,
                description=f"IP change detected: {len(unique_ips)} different IPs observed",
                details={"unique_ips": list(unique_ips), "count": len(unique_ips), "has_trusted": has_trusted}
            )

        return DetectionFinding(
            rule_name="multiple_ip_changes",
            triggered=False,
            severity="LOW",
            score_contribution=0,
            description="Single consistent IP observed"
        )

    def rule_no_baseline(self, event: DNSEvent) -> DetectionFinding:
        """
        Rule 6: Domain has no trusted baseline configured.
        Unknown domains should be monitored but not necessarily flagged as attacks.
        """
        trusted = self._get_trusted_domain(event.domain)
        if not trusted:
            return DetectionFinding(
                rule_name="no_baseline",
                triggered=True,
                severity="LOW",
                score_contribution=5,
                description=f"No trusted baseline configured for domain: {event.domain}",
                details={"domain": event.domain, "recommendation": "Add to trusted domains if legitimate"}
            )

        return DetectionFinding(
            rule_name="no_baseline",
            triggered=False,
            severity="LOW",
            score_contribution=0,
            description="Domain has trusted baseline"
        )

    def rule_dga_entropy(self, event: DNSEvent) -> DetectionFinding:
        """
        Rule 7: Shannon Entropy & DGA Detection.
        High-entropy domains (random strings) indicate DGA or DNS tunneling attempts.
        """
        import math

        domain_part = event.domain.split('.')[0] if event.domain else ""
        if len(domain_part) < 6:
            return DetectionFinding(
                rule_name="dga_entropy",
                triggered=False,
                severity="LOW",
                score_contribution=0,
                description="Domain label too short for entropy check"
            )

        prob = [float(domain_part.count(c)) / len(domain_part) for c in dict.fromkeys(list(domain_part))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

        if entropy >= 4.2 or (len(domain_part) > 15 and entropy >= 3.8):
            return DetectionFinding(
                rule_name="dga_entropy",
                triggered=True,
                severity="HIGH",
                score_contribution=25,
                description=f"High Shannon entropy detected ({entropy:.2f}): Possible DGA or DNS Tunneling",
                details={"entropy": round(entropy, 2), "label": domain_part, "mitre": "T1568.002 / T1071.004"}
            )

        return DetectionFinding(
            rule_name="dga_entropy",
            triggered=False,
            severity="LOW",
            score_contribution=0,
            description=f"Normal domain entropy ({entropy:.2f})"
        )

    def rule_fast_flux(self, event: DNSEvent) -> DetectionFinding:
        """
        Rule 8: Sub-30s Ultra-short TTL Fast-Flux Detection.
        Extremely short TTLs combined with changing IPs indicate Fast-Flux networks.
        """
        if event.ttl is not None and event.ttl <= 30:
            recent_events = self._get_recent_events(event.domain, hours=1)
            unique_ips = {e.response_ip for e in recent_events if e.response_ip}
            if len(unique_ips) >= 2:
                return DetectionFinding(
                    rule_name="fast_flux",
                    triggered=True,
                    severity="HIGH",
                    score_contribution=25,
                    description=f"Fast-Flux indicator: Sub-30s TTL ({event.ttl}s) with {len(unique_ips)} IPs in 1 hour",
                    details={"ttl": event.ttl, "unique_ips": list(unique_ips), "mitre": "T1568.002"}
                )

        return DetectionFinding(
            rule_name="fast_flux",
            triggered=False,
            severity="LOW",
            score_contribution=0,
            description="No fast-flux indicators"
        )

    def run_all_rules(self, event: DNSEvent) -> List[DetectionFinding]:
        """Run all detection rules against a DNS event."""
        rules = [
            self.rule_unexpected_ip,
            self.rule_unexpected_dns_server,
            self.rule_ttl_anomaly,
            self.rule_repeated_suspicious_responses,
            self.rule_multiple_ip_changes,
            self.rule_dga_entropy,
            self.rule_fast_flux,
            self.rule_no_baseline,
        ]

        findings = []
        for rule in rules:
            try:
                finding = rule(event)
                findings.append(finding)
            except Exception as e:
                findings.append(DetectionFinding(
                    rule_name=rule.__name__,
                    triggered=False,
                    severity="LOW",
                    score_contribution=0,
                    description=f"Rule error: {str(e)}"
                ))

        return findings