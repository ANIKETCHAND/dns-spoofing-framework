"""
Risk Scoring Engine for DNS Spoofing Detection.
Calculates risk score (0-100) and severity based on detection findings.
"""
from dataclasses import dataclass
from typing import List, Dict, Any
from enum import Enum

from app.detection.rules import DetectionFinding


class SeverityLevel(str, Enum):
    """Risk severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskAssessment:
    """Complete risk assessment result."""
    risk_score: int  # 0-100
    severity: SeverityLevel
    triggered_rules: List[DetectionFinding]
    summary: str
    recommendations: List[str]


class RiskScorer:
    """
    Calculates risk score based on detection findings.

    Scoring methodology:
    - Each rule contributes a score (0-100)
    - Scores are combined with diminishing returns to prevent overflow
    - Base score starts at 0
    - Maximum possible score is 100
    """

    # Severity thresholds
    SEVERITY_THRESHOLDS = {
        SeverityLevel.LOW: (0, 30),
        SeverityLevel.MEDIUM: (31, 60),
        SeverityLevel.HIGH: (61, 80),
        SeverityLevel.CRITICAL: (81, 100),
    }

    # Rule weights - critical rules have higher base weights
    RULE_WEIGHTS = {
        "unexpected_ip": 1.0,           # Primary indicator
        "unexpected_dns_server": 0.8,   # Strong indicator
        "ttl_anomaly": 0.6,             # Supporting indicator
        "repeated_suspicious": 0.9,     # Strong behavioral indicator
        "multiple_ip_changes": 0.85,    # Strong behavioral indicator
        "dga_entropy": 0.8,             # DGA & Tunneling indicator
        "fast_flux": 0.85,              # Sub-30s TTL fast-flux indicator
        "no_baseline": 0.2,             # Informational only
    }

    def __init__(self):
        pass

    def calculate_score(self, findings: List[DetectionFinding]) -> int:
        """
        Calculate combined risk score from findings.

        Uses a weighted sum with diminishing returns formula:
        score = min(100, sum(weight * contribution) * combination_factor)
        """
        if not findings:
            return 0

        total_weighted_score = 0
        total_weight = 0

        for finding in findings:
            if not finding.triggered:
                continue

            weight = self.RULE_WEIGHTS.get(finding.rule_name, 0.5)
            contribution = finding.score_contribution
            total_weighted_score += weight * contribution
            total_weight += weight

        if total_weight == 0:
            return 0

        # Average weighted score
        avg_score = total_weighted_score / total_weight

        # Apply diminishing returns for multiple findings
        # More findings = higher confidence, but not linear
        num_triggered = sum(1 for f in findings if f.triggered)
        if num_triggered > 1:
            # Boost for multiple independent indicators
            confidence_boost = min(15, (num_triggered - 1) * 5)
            avg_score = min(100, avg_score + confidence_boost)

        return int(round(avg_score))

    def determine_severity(self, risk_score: int) -> SeverityLevel:
        """Determine severity level from risk score."""
        for severity, (min_score, max_score) in self.SEVERITY_THRESHOLDS.items():
            if min_score <= risk_score <= max_score:
                return severity
        return SeverityLevel.CRITICAL  # Fallback for scores > 100

    def generate_summary(self, findings: List[DetectionFinding], risk_score: int) -> str:
        """Generate human-readable summary of the assessment."""
        triggered = [f for f in findings if f.triggered]
        if not triggered:
            return "No suspicious indicators detected. DNS response appears normal."

        severity = self.determine_severity(risk_score)
        rule_descriptions = [f.description for f in triggered]

        if severity == SeverityLevel.CRITICAL:
            prefix = "CRITICAL: Strong evidence of DNS spoofing detected. "
        elif severity == SeverityLevel.HIGH:
            prefix = "HIGH: Multiple indicators suggest possible DNS spoofing. "
        elif severity == SeverityLevel.MEDIUM:
            prefix = "MEDIUM: Some suspicious indicators detected. "
        else:
            prefix = "LOW: Minor anomalies detected. "

        return prefix + "; ".join(rule_descriptions)

    def generate_recommendations(self, findings: List[DetectionFinding], risk_score: int) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recommendations = []
        triggered = [f for f in findings if f.triggered]

        if not triggered:
            recommendations.append("Continue monitoring. No action required.")
            return recommendations

        severity = self.determine_severity(risk_score)

        # Rule-specific recommendations
        rule_names = {f.rule_name for f in triggered}

        if "unexpected_ip" in rule_names:
            recommendations.append(
                "URGENT: Verify the legitimate IP for this domain. "
                "Check DNS records on authoritative nameservers. "
                "Consider blocking the suspicious IP at network perimeter."
            )

        if "unexpected_dns_server" in rule_names:
            recommendations.append(
                "Review DNS server configuration. Ensure clients use only authorized DNS resolvers. "
                "Check for rogue DHCP servers or DNS hijacking."
            )

        if "ttl_anomaly" in rule_names:
            recommendations.append(
                "Investigate TTL anomalies. Very low TTLs may indicate spoofing attempts. "
                "Very high TTLs may indicate cache poisoning attempts."
            )

        if "repeated_suspicious" in rule_names:
            recommendations.append(
                "Active attack likely in progress. Enable enhanced monitoring. "
                "Consider network capture for forensic analysis. "
                "Notify security team immediately."
            )

        if "multiple_ip_changes" in rule_names:
            recommendations.append(
                "Fast-flux or round-robin spoofing detected. "
                "Monitor for domain fluxing techniques. "
                "Check if domain uses legitimate CDN/load balancing."
            )

        if "no_baseline" in rule_names:
            recommendations.append(
                "Add this domain to trusted baseline if legitimate. "
                "Monitor for future anomalies."
            )

        # Severity-based general recommendations
        if severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            recommendations.append(
                "IMMEDIATE: Isolate affected systems. Capture network traffic. "
                "Check for malware or compromised hosts. Review DNS logs."
            )
        elif severity == SeverityLevel.MEDIUM:
            recommendations.append(
                "Increase monitoring frequency. Review recent DNS queries for this domain. "
                "Verify endpoint security status."
            )

        return recommendations

    def assess(self, findings: List[DetectionFinding]) -> RiskAssessment:
        """Perform complete risk assessment."""
        risk_score = self.calculate_score(findings)
        severity = self.determine_severity(risk_score)
        summary = self.generate_summary(findings, risk_score)
        recommendations = self.generate_recommendations(findings, risk_score)

        return RiskAssessment(
            risk_score=risk_score,
            severity=severity,
            triggered_rules=[f for f in findings if f.triggered],
            summary=summary,
            recommendations=recommendations
        )


# Convenience function
def assess_risk(findings: List[DetectionFinding]) -> RiskAssessment:
    """Quick risk assessment function."""
    scorer = RiskScorer()
    return scorer.assess(findings)