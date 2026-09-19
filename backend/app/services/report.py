import html
from typing import Any

from app.db.models import Scan, ScanResult


class ReportService:
    @staticmethod
    def generate_json_report(scan: Scan, result: ScanResult | None) -> dict[str, Any]:
        """Generate canonical JSON report payload."""
        scan_data = {
            "scan_id": str(scan.id),
            "project_name": scan.project_name,
            "status": scan.status,
            "error_message": scan.error_message,
            "spec_filename": scan.spec_filename,
            "source_filename": scan.source_filename,
            "spec_hash": scan.spec_hash,
            "source_hash": scan.source_hash,
            "engine_version": scan.engine_version,
            "rule_set_version": scan.rule_set_version,
            "config_version": scan.config_version,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        }

        if not result:
            return {
                "scan": scan_data,
                "metrics_summary": None,
                "matched_endpoints": [],
                "spec_only_findings": [],
                "source_only_findings": [],
                "correlated_findings": [],
            }

        return {
            "scan": scan_data,
            "metrics_summary": result.metrics_summary,
            "matched_endpoints": result.matched_endpoints,
            "spec_only_findings": result.spec_only_findings,
            "source_only_findings": result.source_only_findings,
            "correlated_findings": result.correlated_findings,
        }

    @staticmethod
    def generate_html_report(scan: Scan, result: ScanResult | None) -> str:
        """Render standalone server-side HTML report with styling and findings cards."""
        project_name = html.escape(scan.project_name)
        status = html.escape(scan.status)
        scan_id = html.escape(str(scan.id))

        if not result:
            err = html.escape(scan.error_message or "Scan failed without result")
            return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Analysis Report - {project_name}</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        .card {{ background: #1e293b; padding: 24px; border-radius: 8px; }}
        .badge-failed {{ background: #ef4444; color: #fff; padding: 4px 8px; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>API Security Report: {project_name}</h1>
        <p><strong>Scan ID:</strong> {scan_id}</p>
        <p><strong>Status:</strong> <span class="badge-failed">{status}</span></p>
        <p><strong>Error Details:</strong> {err}</p>
    </div>
</body>
</html>"""

        metrics = result.metrics_summary
        matched_cnt = metrics.get("matched_endpoints_count", 0)
        spec_count = len(result.spec_only_findings)
        source_count = len(result.source_only_findings)
        corr_count = len(result.correlated_findings)

        corr_rows = ""
        for item in result.correlated_findings:
            title = html.escape(str(item.get("title", "")))
            rule_id = html.escape(str(item.get("rule_id", "")))
            state = html.escape(str(item.get("correlation_state", "")))
            rat = html.escape(str(item.get("rationale", "")))
            ep = item.get("matched_endpoint") or {}
            ep_str = html.escape(f"{ep.get('spec_method', '').upper()} {ep.get('spec_path', '')}")

            corr_rows += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="rule-id">{rule_id}</span>
                    <span class="badge state-{state.lower()}">{state}</span>
                </div>
                <h3>{title}</h3>
                <p><strong>Endpoint:</strong> <code>{ep_str}</code></p>
                <p><strong>Rationale:</strong> {rat}</p>
            </div>
            """

        mb = '<div class="metric-box"><div>'
        mn = '</div><div class="metric-num">'
        cl = "</div></div>"
        grid_html = (
            f'<div class="grid">'
            f"{mb}Matched{mn}{matched_cnt}{cl}"
            f"{mb}Spec-Only{mn}{spec_count}{cl}"
            f"{mb}Source-Only{mn}{source_count}{cl}"
            f"{mb}Correlated{mn}{corr_count}{cl}"
            "</div>"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Security Report - {project_name}</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }}
        .metric-box {{ background: #1e293b; padding: 16px; border-radius: 8px; }}
        .metric-num {{ font-size: 28px; font-weight: bold; color: #38bdf8; }}
        .finding-card {{ background: #1e293b; padding: 20px; border-radius: 8px; }}
        .finding-header {{ display: flex; justify-content: space-between; }}
        .rule-id {{ font-weight: bold; color: #a855f7; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; }}
        .state-supported {{ background: #22c55e; color: #000; }}
        .state-contradicted {{ background: #ef4444; color: #fff; }}
        .state-complementary {{ background: #eab308; color: #000; }}
        .state-inconclusive {{ background: #64748b; color: #fff; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Intelligent API Security Analyzer — Multi-Layer Report</h1>
        <p>Project: <strong>{project_name}</strong> | Scan ID: <code>{scan_id}</code></p>
    </div>

    {grid_html}

    <h2>Correlated Evidence Findings</h2>
    {corr_rows if corr_rows else "<p>No correlated findings detected.</p>"}
</body>
</html>"""
