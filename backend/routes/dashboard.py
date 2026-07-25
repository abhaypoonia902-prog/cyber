from flask import Blueprint, jsonify
from models.models import Analysis, UploadedFile, Threat
from sqlalchemy import func

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.get("/dashboard")
def dashboard():
    total_logs = UploadedFile.query.count()
    analyses = Analysis.query.all()
    threat_count = sum(a.threat_count for a in analyses)
    avg_risk = int(sum(a.risk_score for a in analyses) / len(analyses)) if analyses else 0

    severity_breakdown = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for a in analyses:
        severity_breakdown[a.severity] = severity_breakdown.get(a.severity, 0) + 1

    suspicious_ips = (
        Threat.query.with_entities(Threat.source_ip, func.count(Threat.id))
        .filter(Threat.source_ip.isnot(None))
        .group_by(Threat.source_ip)
        .order_by(func.count(Threat.id).desc())
        .limit(10)
        .all()
    )

    timeline = [{
        "analysis_id": a.id,
        "filename": a.file.original_name,
        "risk_score": a.risk_score,
        "severity": a.severity,
        "created_at": a.created_at.isoformat(),
    } for a in Analysis.query.order_by(Analysis.created_at.desc()).limit(20)]

    return jsonify({
        "total_logs": total_logs,
        "threat_count": threat_count,
        "risk_score": avg_risk,
        "severity_breakdown": severity_breakdown,
        "suspicious_ips": [{"ip": ip, "count": count} for ip, count in suspicious_ips],
        "timeline_events": timeline,
    })