"""
Main API routes for DNS Spoofing Framework dashboard.
"""
import json
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from pydantic import BaseModel

from app.database.models import DNSEvent, Alert, SimulationEvent, TrustedDomain, EventStatus
from app.database.database import get_db, Session
from app.detection.engine import DetectionEngine
from app.dns.simulator import DNSSimulator
from app.dns.parser import extract_dns_from_pcap
from app.dns.monitor import get_available_interfaces, get_monitor_status, start_global_monitor, stop_global_monitor
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()


# ============ Pydantic Models ============
class DNSQueryInput(BaseModel):
    domain: str
    source_ip: str
    query_type: str = "A"
    response_ip: str
    ttl: Optional[int] = None
    dns_server: Optional[str] = None


class SimulationRequest(BaseModel):
    domain: str
    spoofed: bool = False


# ============ GET Endpoints ============

@router.get("/dns-events")
def get_dns_events(
    domain: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100),
    db: Session = Depends(get_db)
):
    """Get filtered DNS events."""
    query = db.query(DNSEvent).order_by(DNSEvent.timestamp.desc())
    if domain:
        query = query.filter(DNSEvent.domain.ilike(f"%{domain}%"))
    if severity:
        query = query.filter(DNSEvent.severity == severity)
    return query.limit(limit).all()


@router.get("/alerts")
def get_alerts(
    severity: Optional[str] = Query(None),
    limit: int = Query(50),
    db: Session = Depends(get_db)
):
    """Get filtered alerts."""
    query = db.query(Alert).order_by(Alert.timestamp.desc())
    if severity:
        query = query.filter(Alert.severity == severity)
    return query.limit(limit).all()


@router.get("/simulation-events")
def get_simulation_events(
    limit: int = Query(50),
    db: Session = Depends(get_db)
):
    """Get simulation events for demo mode."""
    return db.query(SimulationEvent).order_by(SimulationEvent.timestamp.desc()).limit(limit).all()


@router.get("/dashboard-stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics for frontend rendering."""
    try:
        engine = DetectionEngine(db_session=db)
        return engine.get_statistics()
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/charts/events-over-time")
def get_events_over_time(
    hours: int = Query(24, ge=1, le=168),
    interval_minutes: int = Query(60, ge=5, le=1440),
    db: Session = Depends(get_db)
):
    """Get time-series event metrics for charts."""
    try:
        engine = DetectionEngine(db_session=db)
        return engine.get_events_over_time(hours=hours, interval_minutes=interval_minutes)
    except Exception as e:
        logger.error(f"Chart data error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dns-events/{event_id}")
def get_dns_event_detail(
    event_id: int,
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific DNS event."""
    event = db.query(DNSEvent).filter(DNSEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Get related alerts
    alerts = db.query(Alert).filter(Alert.event_id == event_id).all()

    # Parse detection reasons
    detection_reasons = None
    if event.detection_reasons:
        try:
            detection_reasons = json.loads(event.detection_reasons)
        except json.JSONDecodeError:
            detection_reasons = [{"description": event.detection_reasons}]

    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "source_ip": event.source_ip,
        "domain": event.domain,
        "query_type": event.query_type,
        "response_ip": event.response_ip,
        "expected_ip": event.expected_ip,
        "ttl": event.ttl,
        "dns_server": event.dns_server,
        "risk_score": event.risk_score,
        "severity": event.severity,
        "status": event.status,
        "is_simulation": event.is_simulation,
        "detection_reasons": detection_reasons,
        "raw_packet_info": event.raw_packet_info,
        "alerts": [
            {
                "id": a.id,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "acknowledged": a.acknowledged,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None
            }
            for a in alerts
        ]
    }


@router.get("/alerts/{alert_id}")
def get_alert_detail(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """Get detailed alert information."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    event = db.query(DNSEvent).filter(DNSEvent.id == alert.event_id).first()

    return {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "acknowledged": alert.acknowledged,
        "event": {
            "id": event.id if event else None,
            "domain": event.domain if event else None,
            "source_ip": event.source_ip if event else None,
            "dns_server": event.dns_server if event else None,
            "response_ip": event.response_ip if event else None,
            "expected_ip": event.expected_ip if event else None,
            "ttl": event.ttl if event else None,
            "risk_score": event.risk_score if event else None
        }
    }


@router.get("/trusted-domains")
def get_trusted_domains(db: Session = Depends(get_db)):
    """Get all trusted domains."""
    return db.query(TrustedDomain).filter(TrustedDomain.is_active == True).all()


@router.get("/simulation-domains")
def get_simulation_domains():
    """Get available lab domains."""
    simulator = DNSSimulator()
    domains = simulator.get_lab_domains()
    return {
        "domains": [
            {
                "domain": d.domain,
                "legitimate_ip": d.legitimate_ip,
                "simulation_ip": d.simulation_ip
            }
            for d in domains.values()
        ]
    }


# ============ Live Network Sniffing Monitor Endpoints ============

@router.get("/monitor/interfaces")
def get_monitor_interfaces():
    """List available network interfaces for live packet capture."""
    return {"interfaces": get_available_interfaces()}


@router.get("/monitor/status")
def get_live_monitor_status():
    """Get status of the live packet capture monitor."""
    return get_monitor_status()


@router.post("/monitor/start")
def start_live_monitor(interface: Optional[str] = Query(None)):
    """Start live packet capture monitor."""
    return start_global_monitor(interface=interface)


@router.post("/monitor/stop")
def stop_live_monitor():
    """Stop live packet capture monitor."""
    return stop_global_monitor()


# ============ POST Endpoints ============

@router.post("/dns-query")
def analyze_dns_query(query: DNSQueryInput, db: Session = Depends(get_db)):
    """Manually analyze a DNS query response (for testing)."""
    engine = DetectionEngine(db_session=db)
    event = engine.analyze_event_data(
        domain=query.domain,
        source_ip=query.source_ip,
        query_type=query.query_type,
        response_ip=query.response_ip,
        ttl=query.ttl,
        dns_server=query.dns_server,
        is_simulation=False
    )
    return {
        "id": event.id,
        "risk_score": event.risk_score,
        "severity": event.severity,
        "status": event.status
    }


@router.post("/simulate-query")
def simulate_query(request: SimulationRequest):
    """Simulate a DNS query for demo mode."""
    simulator = DNSSimulator()

    if not simulator.is_lab_domain(request.domain):
        raise HTTPException(
            status_code=400,
            detail=f"Domain '{request.domain}' is not in lab configuration. Allowed domains: {list(simulator.get_lab_domains().keys())}"
        )

    if request.spoofed:
        return simulator.simulate_spoofed_query(request.domain)
    else:
        return simulator.simulate_normal_query(request.domain)


@router.post("/simulate-batch")
def simulate_batch(
    count: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Generate a batch of simulation events for demo mode."""
    simulator = DNSSimulator()
    num_domains = max(1, len(simulator.lab_domains))
    iterations = max(1, count // (num_domains * 2))
    results = simulator.run_demo_sequence(iterations=iterations, delay=0.01)
    return {"success": True, "count": len(results), "results": results}


@router.post("/load-trusted-domain")
def load_trusted_domain(
    domain: str,
    expected_ip: str,
    db: Session = Depends(get_db)
):
    """Add a domain to the trusted baseline."""
    trusted = TrustedDomain(
        domain=domain,
        expected_ip=expected_ip,
        expected_ttl_min=300,
        expected_ttl_max=86400,
        is_active=True
    )
    db.add(trusted)
    db.commit()
    return {"domain": domain, "expected_ip": expected_ip}


@router.post("/analyze-pcap")
def analyze_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Analyze an uploaded PCAP file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Validate file extension
    if not file.filename.lower().endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="File must be a .pcap or .pcapng file")

    import tempfile
    import os

    temp_path = None
    try:
        content = file.file.read()
        if len(content) > 100 * 1024 * 1024:  # 100MB limit
            raise HTTPException(status_code=400, detail="File too large (max 100MB)")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(content)
            temp_path = tmp.name

        parsed_records = extract_dns_from_pcap(temp_path)

        analyzed_events = []
        engine = DetectionEngine(db_session=db)

        for record in parsed_records:
            try:
                event = engine.analyze_event_data(
                    domain=record.get("domain", ""),
                    source_ip=record.get("source_ip", "0.0.0.0"),
                    query_type=record.get("query_type", "A"),
                    response_ip=record.get("response_ip"),
                    ttl=record.get("ttl"),
                    dns_server=record.get("dns_server"),
                    is_simulation=False
                )
                analyzed_events.append({
                    "id": event.id,
                    "domain": event.domain,
                    "response_ip": event.response_ip,
                    "risk_score": event.risk_score,
                    "severity": event.severity,
                    "status": event.status
                })
            except Exception as e:
                logger.error(f"Error analyzing PCAP record: {e}")
                continue

        return {
            "success": True,
            "filename": file.filename,
            "records_found": len(parsed_records),
            "events_analyzed": len(analyzed_events),
            "results": analyzed_events
        }

    except Exception as e:
        logger.error(f"PCAP analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


# ============ DELETE Endpoints ============

@router.delete("/alerts/{alert_id}")
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """Delete an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return {"message": "Alert deleted"}


@router.delete("/dns-events/clear-simulation")
def clear_simulation_data(db: Session = Depends(get_db)):
    """Clear all simulation data from database."""
    deleted = db.query(DNSEvent).filter(DNSEvent.is_simulation == True).delete()
    db.commit()
    return {"message": f"Deleted {deleted} simulation events"}


# ============ Security Incident & Threat Intelligence Export ============

@router.get("/reports/export")
def export_security_report(
    format: str = Query("csv", description="Format: csv, json, html"),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Export forensic DNS incident security report with MITRE ATT&CK mapping."""
    from fastapi.responses import Response
    import io
    import csv

    events = db.query(DNSEvent).order_by(DNSEvent.timestamp.desc()).limit(limit).all()

    if format.lower() == "json":
        data = [{
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "domain": e.domain,
            "query_type": e.query_type,
            "source_ip": e.source_ip,
            "response_ip": e.response_ip,
            "expected_ip": e.expected_ip,
            "risk_score": e.risk_score,
            "severity": e.severity,
            "status": e.status,
            "mitre_attack": "T1557.006 / T1071.004 / T1568.002",
            "detection_reasons": json.loads(e.detection_reasons) if e.detection_reasons else []
        } for e in events]
        return Response(content=json.dumps(data, indent=2), media_type="application/json", headers={"Content-Disposition": "attachment; filename=dns_threat_report.json"})

    elif format.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Timestamp", "Domain", "Type", "Source IP", "Response IP", "Expected IP", "Risk Score", "Severity", "Status", "MITRE ATT&CK"])
        for e in events:
            writer.writerow([
                e.id,
                e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "",
                e.domain,
                e.query_type,
                e.source_ip,
                e.response_ip or "",
                e.expected_ip or "",
                e.risk_score,
                e.severity,
                e.status,
                "T1557.006 (DNS Spoofing) / T1568.002 (Fast-Flux)"
            ])
        return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=dns_threat_report.csv"})

    elif format.lower() == "html":
        # Executive Forensic Summary HTML
        critical_count = sum(1 for e in events if e.severity == "CRITICAL")
        high_count = sum(1 for e in events if e.severity == "HIGH")
        suspicious_count = sum(1 for e in events if e.severity in ["MEDIUM", "HIGH", "CRITICAL"])

        rows_html = "".join([f"""
            <tr>
                <td>{e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else 'N/A'}</td>
                <td><strong>{e.domain}</strong></td>
                <td>{e.expected_ip or 'N/A'}</td>
                <td style="color:{'#ef4444' if e.response_ip != e.expected_ip and e.expected_ip else '#c9d1d9'};">{e.response_ip or 'N/A'}</td>
                <td><strong>{e.risk_score}</strong></td>
                <td><span style="padding: 3px 8px; border-radius:4px; font-weight:bold; background:{'rgba(248,113,113,0.2)' if e.severity=='CRITICAL' else 'rgba(249,115,22,0.2)' if e.severity=='HIGH' else 'rgba(251,191,36,0.2)' if e.severity=='MEDIUM' else 'rgba(52,211,153,0.2)'}; color:{'#f87171' if e.severity=='CRITICAL' else '#f97316' if e.severity=='HIGH' else '#fbbf24' if e.severity=='MEDIUM' else '#34d399'};">{e.severity}</span></td>
            </tr>
        """ for e in events[:50]])

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>DNS Threat Intelligence Executive Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 40px; margin: 0; }}
        .report-header {{ border-bottom: 2px solid #38bdf8; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        .badge {{ background: #38bdf8; color: #000; padding: 4px 12px; border-radius: 4px; font-weight: bold; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; text-align: center; }}
        .card h3 {{ margin: 0; font-size: 32px; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }}
        th, td {{ border: 1px solid #30363d; padding: 10px 14px; text-align: left; }}
        th {{ background: #161b22; color: #38bdf8; }}
        tr:nth-child(even) {{ background: rgba(22, 27, 34, 0.5); }}
    </style>
</head>
<body>
    <div class="report-header">
        <div>
            <h1 style="margin:0; color:#38bdf8;">🛡️ DNS Threat Intelligence Executive Report</h1>
            <p style="margin:5px 0 0 0; color:#8b949e;">Forensic Event Analysis & MITRE ATT&CK Threat Mapping</p>
        </div>
        <span class="badge">CONFIDENTIAL LAB REPORT</span>
    </div>

    <div class="summary-grid">
        <div class="card"><h3>{len(events)}</h3><p style="margin:5px 0 0 0; color:#8b949e;">Events Analyzed</p></div>
        <div class="card"><h3 style="color:#fbbf24;">{suspicious_count}</h3><p style="margin:5px 0 0 0; color:#8b949e;">Suspicious Events</p></div>
        <div class="card"><h3 style="color:#f97316;">{high_count}</h3><p style="margin:5px 0 0 0; color:#8b949e;">High Risk Findings</p></div>
        <div class="card"><h3 style="color:#f87171;">{critical_count}</h3><p style="margin:5px 0 0 0; color:#8b949e;">Critical Alerts</p></div>
    </div>

    <h2>🎯 MITRE ATT&CK Matrix Mapping</h2>
    <ul>
        <li><strong>T1557.006 (Adversary-in-the-Middle: Multi-Stage DNS Spoofing)</strong>: Detected via unexpected IP responses differing from trusted baselines.</li>
        <li><strong>T1568.002 (Dynamic Resolution: Fast-Flux DNS)</strong>: Detected via sub-30s TTLs combined with rapid IP fluxing.</li>
        <li><strong>T1071.004 (Application Layer Protocol: DNS Tunneling / DGA)</strong>: Detected via high Shannon entropy domain labels.</li>
    </ul>

    <h2>📋 Analyzed DNS Events</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Domain</th>
                <th>Expected IP</th>
                <th>Received IP</th>
                <th>Risk Score</th>
                <th>Severity</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
</body>
</html>"""
        return Response(content=html_content, media_type="text/html", headers={"Content-Disposition": "inline; filename=dns_threat_report.html"})

    raise HTTPException(status_code=400, detail="Invalid format. Supported: csv, json, html")