import json
from pathlib import Path

import pytest
from app.api.v1 import research


def test_benchmark_api_reads_published_phase7_artifact_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(research, "REPORTS_DIR", tmp_path)
    phase7 = tmp_path / "phase7"
    phase7.mkdir()
    expected = {
        "metrics.json": {"dataset_version": "6.0.0"},
        "external/metrics.json": {"dataset_version": "7.3.0"},
        "combined/metrics.json": {"dataset_version": "combined"},
        "phase7/confidence_intervals.json": [{"metric": "precision"}],
        "phase7/mode_comparison.json": [
            {"metric": "precision", "statistically_significant": False}
        ],
        "phase7/error_analysis.json": {"total_errors_analyzed": 19},
    }
    for relative_path, payload in expected.items():
        artifact = tmp_path / relative_path
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps(payload), encoding="utf-8")

    # These names were previously requested by the API but are not published artifacts.
    (phase7 / "mode_comparisons.json").write_text("[]", encoding="utf-8")
    (phase7 / "error_taxonomy.json").write_text("{}", encoding="utf-8")

    from app.core.security import ClientIdentity

    response = research.get_benchmarks(_client=ClientIdentity(client_id="test"))

    assert response["baseline"] == expected["metrics.json"]
    assert response["external"] == expected["external/metrics.json"]
    assert response["combined"] == expected["combined/metrics.json"]
    assert (
        response["phase7"]["confidence_intervals"] == expected["phase7/confidence_intervals.json"]
    )
    assert response["phase7"]["mode_comparisons"] == expected["phase7/mode_comparison.json"]
    assert response["phase7"]["error_analysis"] == expected["phase7/error_analysis.json"]
