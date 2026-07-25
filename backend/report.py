import json
from pathlib import Path
from config import Config

class ReportService:

    def build(self, analysis_record, analysis_data: dict) -> dict:
        recommendations = []

        if analysis_data.get("brute_force", {}).get("flagged_ips"):
            recommendations.append("Block flagged IPs and enable fail2ban.")

        if analysis_data.get("intrusion", {}).get("event_count", 0) > 0:
            recommendations.append("Review WAF rules and sanitize user inputs.")

        if analysis_data.get("port_scan", {}).get("event_count", 0) > 0:
            recommendations.append("Restrict exposed ports and monitor reconnaissance traffic.")

        if not recommendations:
            recommendations.append("No immediate action required. Continue monitoring.")

        report = {
            "analysis_id": analysis_record.id,
            "summary": {
                "filename": analysis_record.file.original_name,
                "risk_score": analysis_record.risk_score,
                "severity": analysis_record.severity,
                "threat_count": analysis_record.threat_count,
                "total_lines": analysis_record.total_lines,
            },
            "risk_score": analysis_record.risk_score,
            "threat_details": analysis_data.get("threats", []),
            "recommendations": recommendations,
            "analysis": analysis_data,
        }

        Config.REPORT_DIR.mkdir(parents=True, exist_ok=True)

        path = Config.REPORT_DIR / f"report_{analysis_record.id}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        return report, str(path)

    def build_preview(self, analysis_data: dict, filename: str, fmt: str) -> str:

        lines = [
            "=" * 60,
            "LOGSENTINEL ANALYSIS REPORT",
            "=" * 60,
            f"File: {filename}",
            f"Format: {fmt}",
            f"Risk Score: {analysis_data.get('risk_score', 0)}/100",
            f"Severity: {analysis_data.get('severity', 'low').upper()}",
            f"Threats: {len(analysis_data.get('threats', []))}",
            "",
            "RECOMMENDATIONS",
            "-" * 60,
        ]

        for t in analysis_data.get("threats", [])[:20]:
            lines.append(
                f"- [{t.get('severity','').upper()}] "
                f"{t.get('category')}: "
                f"{t.get('message','')}"
            )

        lines.extend([
            "",
            "=" * 60,
            "End of Report"
        ])

        return "\n".join(lines)