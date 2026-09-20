from pathlib import Path

from app.evaluation.reporter import generate_html_report, generate_json_artifacts
from app.evaluation.runner import run_evaluation_experiment


def main() -> None:
    print("==========================================================================")
    print("        INTELLIGENT API SECURITY ANALYZER — PHASE 6 EVALUATION          ")
    print("==========================================================================")
    print("Executing frozen Phase 1-5 analyzer across 24 benchmark cases in 3 modes...\n")

    report_data = run_evaluation_experiment()

    reports_dir = Path("evaluation/reports")
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


if __name__ == "__main__":
    main()
