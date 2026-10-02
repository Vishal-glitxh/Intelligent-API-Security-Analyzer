import argparse
from pathlib import Path

from app.evaluation.reporter import generate_html_report, generate_json_artifacts
from app.evaluation.runner import run_evaluation_experiment


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Execute Intelligent API Security Analyzer Research Evaluation (Phase 6)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("evaluation/reports"),
        help="Directory where generated JSON and HTML evaluation reports are saved",
    )
    parser.add_argument(
        "--phase7-statistics",
        action="store_true",
        default=False,
        help="Generate Phase 7 95%% CIs, mode comparisons, and error taxonomy artifacts",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--deterministic",
        action="store_true",
        default=True,
        help="Generate deterministic report metadata matching published baseline (default)",
    )
    group.add_argument(
        "--dynamic",
        action="store_false",
        dest="deterministic",
        help="Generate fresh dynamic UUID and execution timestamp for new experimental run",
    )

    args = parser.parse_args()

    print("==========================================================================")
    print("        INTELLIGENT API SECURITY ANALYZER — PHASE 6 EVALUATION          ")
    print("==========================================================================")
    print("Executing frozen Phase 1-5 analyzer across 24 benchmark cases in 3 modes...\n")

    report_data = run_evaluation_experiment(deterministic=args.deterministic)

    reports_dir = args.output_dir
    generate_json_artifacts(report_data, reports_dir)
    html_file = generate_html_report(report_data, reports_dir)

    modes = report_data.mode_results
    spec_mode = modes.get("SPEC_ONLY")
    src_mode = modes.get("SOURCE_ONLY")
    corr_mode = modes.get("CORRELATED")

    def fmt(val: float | None) -> str:
        return f"{val:.4f}" if val is not None else "N/A"

    print("\n--------------------------------------------------------------------------")
    print("DIMENSION A: SECURITY DETECTION EVALUATION SUMMARY")
    print("--------------------------------------------------------------------------")
    print(f"{'Metric':<20} | {'SPEC_ONLY':<12} | {'SOURCE_ONLY':<12} | {'CORRELATED':<12}")
    print("--------------------------------------------------------------------------")

    for metric in ("Precision", "Recall", "F1", "FPR", "FNR", "TP", "FP", "FN", "TN"):
        attr = metric.lower()
        v_spec = getattr(spec_mode.dimension_a.overall_metrics, attr) if spec_mode else None
        v_src = getattr(src_mode.dimension_a.overall_metrics, attr) if src_mode else None
        v_corr = getattr(corr_mode.dimension_a.overall_metrics, attr) if corr_mode else None

        s_str = str(v_spec) if isinstance(v_spec, int) else fmt(v_spec)
        src_str = str(v_src) if isinstance(v_src, int) else fmt(v_src)
        c_str = str(v_corr) if isinstance(v_corr, int) else fmt(v_corr)

        print(f"{metric:<20} | {s_str:<12} | {src_str:<12} | {c_str:<12}")

    print("--------------------------------------------------------------------------")
    print("\nEVIDENCE COMPLETENESS & EXPLAINABILITY RUBRICS")
    print("--------------------------------------------------------------------------")
    comp_spec = fmt(spec_mode.evidence_completeness.score) if spec_mode else "N/A"
    comp_src = fmt(src_mode.evidence_completeness.score) if src_mode else "N/A"
    comp_corr = fmt(corr_mode.evidence_completeness.score) if corr_mode else "N/A"

    exp_spec = fmt(spec_mode.explainability.score) if spec_mode else "N/A"
    exp_src = fmt(src_mode.explainability.score) if src_mode else "N/A"
    exp_corr = fmt(corr_mode.explainability.score) if corr_mode else "N/A"

    print(f"{'Completeness Score':<20} | {comp_spec:<12} | {comp_src:<12} | {comp_corr:<12}")
    print(f"{'Explainability Score':<20} | {exp_spec:<12} | {exp_src:<12} | {exp_corr:<12}")

    print("\n--------------------------------------------------------------------------")
    print("DIMENSION B & C RESULTS (CORRELATED MODE)")
    print("--------------------------------------------------------------------------")
    if corr_mode:
        print(f"Dimension B Correlation Accuracy : {fmt(corr_mode.dimension_b.score.accuracy)}")
        print(f"Dimension C Endpoint Match Acc.  : {fmt(corr_mode.dimension_c.score.accuracy)}")

    print(f"\nEvaluation reports saved to: {reports_dir.resolve()}")
    print(f"HTML Report: {html_file.resolve()}")
    print("==========================================================================\n")

    if args.phase7_statistics:
        from app.evaluation.reporter import generate_phase7_artifacts, generate_phase7_html_report
        from app.evaluation.statistics import run_phase7_statistical_analysis

        print("Executing Phase 7 Statistical Analysis & Confidence Interval Generation...")
        stats_result = run_phase7_statistical_analysis(report_data)
        p7_dir = reports_dir / "phase7" if reports_dir.name != "phase7" else reports_dir
        generate_phase7_artifacts(stats_result, p7_dir)
        p7_html = generate_phase7_html_report(stats_result, p7_dir)

        print("\n--------------------------------------------------------------------------")
        print("PHASE 7 STATISTICAL ANALYSIS & CONFIDENCE INTERVALS (95% CI)")
        print("--------------------------------------------------------------------------")
        for ci in stats_result.confidence_intervals:
            m_name = ci["metric"]
            mode = ci["mode"]
            est = f"{ci['estimate']:.4f}" if ci["estimate"] is not None else "N/A"
            low = f"{ci['lower']:.4f}" if ci["lower"] is not None else "N/A"
            up = f"{ci['upper']:.4f}" if ci["upper"] is not None else "N/A"
            method = ci["method"]
            print(f"{mode:<12} | {m_name:<36} | {est:<8} | [{low}, {up}] ({method})")

        print("--------------------------------------------------------------------------")
        print(f"Phase 7 artifacts generated in: {p7_dir.resolve()}")
        print(f"Phase 7 HTML Report: {p7_html.resolve()}")
        print("==========================================================================\n")


if __name__ == "__main__":
    main()
