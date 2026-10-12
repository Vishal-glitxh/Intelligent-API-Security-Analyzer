import json
from pathlib import Path
from typing import Any

from app.core.security import ClientIdentity, get_current_client, require_api_access_token
from fastapi import APIRouter, Depends

router = APIRouter(
    prefix="/research",
    tags=["research"],
    dependencies=[Depends(require_api_access_token)],
)

REPORTS_DIR = Path("evaluation/reports")


def _read_json_if_exists(file_path: Path) -> Any | None:
    if file_path.exists():
        try:
            with open(file_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


@router.get("/benchmarks")
def get_benchmarks(
    _client: ClientIdentity = Depends(get_current_client),
) -> dict[str, Any]:
    """Retrieve Phase 6 and Phase 7 research benchmark evaluations and statistics."""
    baseline_metrics = _read_json_if_exists(REPORTS_DIR / "metrics.json")
    external_metrics = _read_json_if_exists(REPORTS_DIR / "external" / "metrics.json")
    combined_metrics = _read_json_if_exists(REPORTS_DIR / "combined" / "metrics.json")
    ci_data = _read_json_if_exists(REPORTS_DIR / "phase7" / "confidence_intervals.json")
    mode_comp = _read_json_if_exists(REPORTS_DIR / "phase7" / "mode_comparisons.json")
    taxonomy = _read_json_if_exists(REPORTS_DIR / "phase7" / "error_taxonomy.json")

    return {
        "baseline": baseline_metrics,
        "external": external_metrics,
        "combined": combined_metrics,
        "phase7": {
            "confidence_intervals": ci_data,
            "mode_comparisons": mode_comp,
            "error_taxonomy": taxonomy,
        },
    }
