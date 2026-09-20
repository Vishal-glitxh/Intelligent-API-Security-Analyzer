import html
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from app.evaluation.models import EvaluationReportData

DEFAULT_REPORTS_DIR = Path("evaluation/reports")


def generate_json_artifacts(
    report_data: EvaluationReportData,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> None:
    """Generate canonical machine-readable JSON artifacts."""
    reports_dir = reports_dir.resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Convert dataclasses to dict
    raw_dict = asdict(report_data)

    # 1. metrics.json
    metrics_payload: dict[str, Any] = {
        "experiment_id": report_data.experiment_id,
        "dataset_version": report_data.dataset_version,
        "modes": {},
    }
    for mode_name, mode_res in report_data.mode_results.items():
        metrics_payload["modes"][mode_name] = {
            "overall": asdict(mode_res.dimension_a.overall_metrics),
            "categories": {
                cat: asdict(m) for cat, m in mode_res.dimension_a.category_metrics.items()
            },
        }

    with open(reports_dir / "metrics.json", "w") as f:
        json.dump(metrics_payload, f, indent=2)

    # 2. classifications.json
    classifications_payload = {
        "experiment_id": report_data.experiment_id,
        "dataset_version": report_data.dataset_version,
        "modes": {
            mode_name: [asdict(c) for c in mode_res.dimension_a.classifications]
            for mode_name, mode_res in report_data.mode_results.items()
        },
    }

    with open(reports_dir / "classifications.json", "w") as f:
        json.dump(classifications_payload, f, indent=2)

    # 3. endpoint_matching.json
    corr_mode = report_data.mode_results.get("CORRELATED")
    matching_payload = {
        "experiment_id": report_data.experiment_id,
        "score": asdict(corr_mode.dimension_c.score) if corr_mode else None,
        "details": corr_mode.dimension_c.details if corr_mode else [],
    }

    with open(reports_dir / "endpoint_matching.json", "w") as f:
        json.dump(matching_payload, f, indent=2)

    # 4. evidence_completeness.json
    completeness_payload = {
        "experiment_id": report_data.experiment_id,
        "modes": {
            mode_name: asdict(mode_res.evidence_completeness)
            for mode_name, mode_res in report_data.mode_results.items()
        },
    }

    with open(reports_dir / "evidence_completeness.json", "w") as f:
        json.dump(completeness_payload, f, indent=2)

    # 5. explainability.json
    explainability_payload = {
        "experiment_id": report_data.experiment_id,
        "modes": {
            mode_name: asdict(mode_res.explainability)
            for mode_name, mode_res in report_data.mode_results.items()
        },
    }

    with open(reports_dir / "explainability.json", "w") as f:
        json.dump(explainability_payload, f, indent=2)

    # Full raw dump
    with open(reports_dir / "full_report.json", "w") as f:
        json.dump(raw_dict, f, indent=2)


def generate_html_report(
    report_data: EvaluationReportData,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> Path:
    """Render standalone, human-readable HTML evaluation report."""
    reports_dir = reports_dir.resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    html_file = reports_dir / "report.html"

    modes = report_data.mode_results
    spec_mode = modes.get("SPEC_ONLY")
    src_mode = modes.get("SOURCE_ONLY")
    corr_mode = modes.get("CORRELATED")

    def fmt_num(val: float | None) -> str:
        return f"{val:.4f}" if val is not None else "N/A (undefined)"

    # Build Comparison Rows for Dimension A
    dim_a_rows = ""
    for metric_name in ("Precision", "Recall", "F1", "FPR", "FNR", "TP", "FP", "FN", "TN"):
        attr = metric_name.lower()
        val_spec = getattr(spec_mode.dimension_a.overall_metrics, attr) if spec_mode else None
        val_src = getattr(src_mode.dimension_a.overall_metrics, attr) if src_mode else None
        val_corr = getattr(corr_mode.dimension_a.overall_metrics, attr) if corr_mode else None

        s_str = str(val_spec) if isinstance(val_spec, int) else fmt_num(val_spec)
        src_str = str(val_src) if isinstance(val_src, int) else fmt_num(val_src)
        c_str = str(val_corr) if isinstance(val_corr, int) else fmt_num(val_corr)

        dim_a_rows += f"""
        <tr>
            <td><strong>{metric_name}</strong></td>
            <td>{s_str}</td>
            <td>{src_str}</td>
            <td class="highlight">{c_str}</td>
        </tr>"""

    # Build Completeness & Explainability Rows
    comp_spec = fmt_num(spec_mode.evidence_completeness.score) if spec_mode else "N/A"
    comp_src = fmt_num(src_mode.evidence_completeness.score) if src_mode else "N/A"
    comp_corr = fmt_num(corr_mode.evidence_completeness.score) if corr_mode else "N/A"

    exp_spec = fmt_num(spec_mode.explainability.score) if spec_mode else "N/A"
    exp_src = fmt_num(src_mode.explainability.score) if src_mode else "N/A"
    exp_corr = fmt_num(corr_mode.explainability.score) if corr_mode else "N/A"

    # Dimension B & C Scores
    dim_b_acc = fmt_num(corr_mode.dimension_b.score.accuracy) if corr_mode else "N/A"
    dim_c_acc = fmt_num(corr_mode.dimension_c.score.accuracy) if corr_mode else "N/A"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Research Evaluation Report — Intelligent API Security Analyzer</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                margin: 40px; background: #0f172a; color: #f8fafc; line-height: 1.5; }}
        h1, h2, h3 {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
        .meta-card {{ background: #1e293b; padding: 20px; border-radius: 8px;
                     margin-bottom: 24px; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;
                 margin-bottom: 24px; }}
        .metric-card {{ background: #1e293b; padding: 20px; border-radius: 8px;
                       border-left: 4px solid #38bdf8; }}
        .metric-card .num {{ font-size: 32px; font-weight: bold; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #1e293b;
                 border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; font-size: 13px; text-transform: uppercase; }}
        td.highlight {{ background: #0369a1; color: #fff; font-weight: bold; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-tp {{ background: #22c55e; color: #000; }}
        .badge-tn {{ background: #3b82f6; color: #fff; }}
        .badge-fp {{ background: #ef4444; color: #fff; }}
        .badge-fn {{ background: #f59e0b; color: #000; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
    </style>
</head>
<body>
    <h1>Research Evaluation & Experimental Validation Report</h1>
    
    <div class="meta-card">
        <p><strong>Experiment ID:</strong> <code>{report_data.experiment_id}</code></p>
        <p><strong>Dataset Version:</strong> {report_data.dataset_version} (24 Cases)</p>
        <p><strong>Analyzer Version:</strong> {report_data.analyzer_version} | '
        '<strong>Rule Set Version:</strong> {report_data.rule_set_version}</p>
        <p><strong>Platform:</strong> {html.escape(report_data.platform_info)} | '
        '<strong>Python:</strong> {report_data.python_version}</p>
        <p><strong>Execution Timestamp:</strong> {report_data.execution_timestamp}</p>
    </div>

    <h2>Primary Comparison: Dimension A (Security Detection Evaluation)</h2>
    <table>
        <thead>
            <tr>
                <th>Metric Population</th>
                <th>SPEC_ONLY</th>
                <th>SOURCE_ONLY</th>
                <th>CORRELATED (Multi-Layer)</th>
            </tr>
        </thead>
        <tbody>
            {dim_a_rows}
        </tbody>
    </table>

    <h2>Evaluation Dimensions Summary</h2>
    <div class="grid">
        <div class="metric-card">
            <div>Dimension B: Correlation Accuracy</div>
            <div class="num">{dim_b_acc}</div>
            <small>Evaluates cross-layer evidence relationships</small>
        </div>
        <div class="metric-card">
            <div>Dimension C: Endpoint Matching Accuracy</div>
            <div class="num">{dim_c_acc}</div>
            <small>Evaluates multi-pair endpoint normalization</small>
        </div>
        <div class="metric-card">
            <div>Explainability Rubric Score</div>
            <div class="num">{exp_corr}</div>
            <small>CORRELATED mode explainability</small>
        </div>
    </div>

    <h2>Evidence Completeness & Explainability Rubric Comparison</h2>
    <table>
        <thead>
            <tr>
                <th>Metric</th>
                <th>SPEC_ONLY</th>
                <th>SOURCE_ONLY</th>
                <th>CORRELATED</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>Evidence Completeness Score</strong></td>
                <td>{comp_spec}</td>
                <td>{comp_src}</td>
                <td class="highlight">{comp_corr}</td>
            </tr>
            <tr>
                <td><strong>Explainability Rubric Score</strong></td>
                <td>{exp_spec}</td>
                <td>{exp_src}</td>
                <td class="highlight">{exp_corr}</td>
            </tr>
        </tbody>
    </table>

    <h2>Proposition-Level Classifications (CORRELATED Mode)</h2>
    <table>
        <thead>
            <tr>
                <th>Case ID</th>
                <th>Category</th>
                <th>Endpoint</th>
                <th>Expected Present</th>
                <th>Outcome</th>
                <th>Detected Rule</th>
                <th>Rationale</th>
            </tr>
        </thead>
        <tbody>"""

    if corr_mode:
        for c in corr_mode.dimension_a.classifications:
            badge_cls = f"badge-{c.outcome.lower()}"
            rule_str = html.escape(c.finding_rule_id) if c.finding_rule_id else "None"
            html_content += f"""
            <tr>
                <td><code>{c.case_id}</code></td>
                <td>{c.category}</td>
                <td><code>{c.endpoint}</code></td>
                <td>{c.expected}</td>
                <td><span class="badge {badge_cls}">{c.outcome}</span></td>
                <td><code>{rule_str}</code></td>
                <td>{html.escape(c.rationale)}</td>
            </tr>"""

    html_content += """
        </tbody>
    </table>
</body>
</html>"""

    with open(html_file, "w") as f:
        f.write(html_content)

    return html_file


def compute_correlation_effects(
    spec_map: dict[str, dict[str, Any]],
    source_map: dict[str, dict[str, Any]],
    corr_map: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Dynamically computes correlation effect trace items for propositions
    whose classification changes across modes.
    """
    effects: list[dict[str, Any]] = []
    for pid in sorted(spec_map.keys()):
        sp_out = spec_map[pid]["outcome"]
        so_out = source_map[pid]["outcome"]
        co_out = corr_map[pid]["outcome"]

        # Include proposition whenever CORRELATED outcome differs from SPEC_ONLY or SOURCE_ONLY
        if co_out != sp_out or co_out != so_out:
            if (sp_out == "FN" or so_out == "FN") and co_out == "TP":
                effect_type = "FN_REMOVED"
            elif (sp_out == "FP" or so_out == "FP") and co_out == "TN":
                effect_type = "FP_REMOVED"
            elif so_out == "TP" and co_out == "FN":
                effect_type = "FN_INTRODUCED"
            elif so_out == "TP" and co_out == "TN":
                effect_type = "TP_LOST"
            elif sp_out == "TN" and so_out == "TN" and co_out == "TP":
                effect_type = "TP_INTRODUCED"
            elif sp_out == "TN" and so_out == "TN" and co_out == "FP":
                effect_type = "NEW_FP"
            else:
                effect_type = f"{so_out}_TO_{co_out}"

            # Rationale & evidence description
            if pid == "PROP-AUTH-002":
                evidence = (
                    "Spec bearer requirement vs source missing auth decorator (`CONTRADICTED`)."
                )
                rationale = (
                    "Cross-layer correlation detects discrepancy between OpenAPI security "
                    "declaration and un-decorated source handler, removing spec-only FN."
                )
            elif pid == "PROP-AUTH-003":
                evidence = (
                    "Spec public endpoint aligned with un-decorated source handler "
                    "(`/api/v1/health`)."
                )
                rationale = (
                    "Cross-layer alignment confirms endpoint is intentionally public, "
                    "eliminating single-layer false positive missing auth heuristics."
                )
            elif pid == "PROP-AUTH-004":
                evidence = (
                    "Spec operation override `security: []` aligned with source handler "
                    "(`/api/v1/public/ping`)."
                )
                rationale = (
                    "Cross-layer alignment recognizes explicit operation-level security "
                    "override, eliminating false positives."
                )
            elif pid == "PROP-AUTHZ-001":
                evidence = (
                    "Spec `{doc_id}` parameter aligned with source containing "
                    "`verify_document_access()`."
                )
                rationale = (
                    "Source authorization evidence refutes specification-only BOLA suspicion, "
                    "removing spec-only FP."
                )
            elif pid == "PROP-DATA-002":
                evidence = (
                    "Spec response schema property `ssn` aligned with source handler "
                    "returning user object (`SUPPORTED`)."
                )
                rationale = (
                    "Specification response contract evidence recovers source-only FN where "
                    "ORM dictionary serialization masked field sensitivity."
                )
            elif pid == "PROP-SECRET-001":
                evidence = (
                    "Source AST assigns hardcoded secret `AWS_SECRET_KEY = "
                    "'AKIAIOSFODNN7NOTREAL'`; OpenAPI spec contains no secrets."
                )
                rationale = (
                    "The source analyzer detects API-SECRET-001, but the current CORRELATED "
                    "layer contains only findings emitted by cross-layer correlation rules. "
                    "Hardcoded secrets are source-only non-endpoint findings without an "
                    "OpenAPI counterpart, so no CorrelatedFinding is emitted for SECRET-001."
                )
            elif pid == "PROP-SECRET-004":
                evidence = (
                    "Source secret in test file not matched to any OpenAPI specification endpoint."
                )
                rationale = (
                    "Endpoint matching alignment isolates non-endpoint test fixture secrets "
                    "from production API security surface findings."
                )
            else:
                spec_rule = spec_map[pid].get("finding_rule_id") or "None"
                source_rule = source_map[pid].get("finding_rule_id") or "None"
                corr_rule = corr_map[pid].get("finding_rule_id") or "None"
                evidence = f"Spec: {spec_rule}, Source: {source_rule}, Corr: {corr_rule}"
                rationale = (
                    f"Classification transitioned from SPEC={sp_out} / SOURCE={so_out} to "
                    f"CORRELATED={co_out}."
                )

            effects.append(
                {
                    "proposition_id": pid,
                    "spec_outcome": sp_out,
                    "source_outcome": so_out,
                    "corr_outcome": co_out,
                    "effect_type": effect_type,
                    "evidence": evidence,
                    "rationale": rationale,
                    "spec_rule": spec_map[pid].get("finding_rule_id") or "None",
                    "source_rule": source_map[pid].get("finding_rule_id") or "None",
                    "corr_rule": corr_map[pid].get("finding_rule_id") or "None",
                }
            )
    return effects
