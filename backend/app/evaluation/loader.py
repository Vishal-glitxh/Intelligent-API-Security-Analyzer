import logging
from pathlib import Path
from typing import Any

import yaml

from app.evaluation.models import (
    CaseGroundTruth,
    ExpectedCorrelationState,
    ExpectedEndpointPair,
    GroundTruthLabel,
    SecurityProposition,
)

logger = logging.getLogger(__name__)

DEFAULT_DATASET_DIR = Path("evaluation/dataset")


def load_dataset(dataset_dir: Path = DEFAULT_DATASET_DIR) -> tuple[CaseGroundTruth, ...]:
    """Load benchmark ground truth cases and validate dataset integrity."""
    dataset_dir = dataset_dir.resolve()
    gt_master_path = dataset_dir / "ground_truth.yaml"

    if not gt_master_path.exists():
        raise FileNotFoundError(f"Ground truth master file not found at {gt_master_path}")

    with open(gt_master_path) as f:
        master_data: dict[str, Any] = yaml.safe_load(f)

    raw_cases: list[dict[str, Any]] = master_data.get("cases", [])
    if not raw_cases:
        raise ValueError("Ground truth dataset contains no cases.")

    loaded_cases: list[CaseGroundTruth] = []
    seen_ids: set[str] = set()

    for item in raw_cases:
        case_id = item["case_id"]
        if case_id in seen_ids:
            raise ValueError(f"Duplicate case_id '{case_id}' detected in dataset.")
        seen_ids.add(case_id)

        # Parse SecurityPropositions
        propositions: list[SecurityProposition] = []
        for p in item.get("propositions", []):
            propositions.append(
                SecurityProposition(
                    proposition_id=p["proposition_id"],
                    category=p["category"],
                    endpoint=p["endpoint"],
                    method=p["method"].upper(),
                    condition=p["condition"],
                    expected=bool(p["expected"]),
                )
            )

        # Parse ExpectedEndpointPairs
        pairs: list[ExpectedEndpointPair] = []
        for pair in item.get("expected_endpoint_pairs", []):
            pairs.append(
                ExpectedEndpointPair(
                    pair_id=pair["pair_id"],
                    spec_path=pair["spec_path"],
                    spec_method=pair["spec_method"].upper(),
                    source_path=pair.get("source_path"),
                    source_method=pair.get("source_method").upper()
                    if pair.get("source_method")
                    else None,
                    expected_match_state=pair["expected_match_state"],
                )
            )

        # Parse ExpectedCorrelationStates
        correlations: list[ExpectedCorrelationState] = []
        for corr in item.get("expected_correlations", []):
            correlations.append(
                ExpectedCorrelationState(
                    target_id=corr["target_id"],
                    category=corr["category"],
                    endpoint=corr["endpoint"],
                    method=corr["method"].upper(),
                    expected_state=corr["expected_state"],
                )
            )

        case_gt = CaseGroundTruth(
            case_id=case_id,
            category=item["category"],
            description=item["description"],
            ground_truth_label=GroundTruthLabel(item["ground_truth_label"]),
            propositions=tuple(propositions),
            expected_endpoint_pairs=tuple(pairs),
            expected_correlations=tuple(correlations),
            rationale=item.get("rationale", ""),
            dataset_version=item.get("dataset_version", "6.0.0"),
            evaluation_role=item.get("evaluation_role", "FINAL"),
        )
        loaded_cases.append(case_gt)

    if len(loaded_cases) != 24:
        logger.warning(
            f"Expected benchmark size of 24 cases, but dataset contains {len(loaded_cases)} cases."
        )

    return tuple(loaded_cases)


def get_case_files(case_id: str, dataset_dir: Path = DEFAULT_DATASET_DIR) -> tuple[Path, Path]:
    """Retrieve OpenAPI spec file path and source directory for a given case."""
    case_dir = (dataset_dir / "cases" / case_id).resolve()
    spec_path = case_dir / "openapi.yaml"
    source_dir = case_dir / "source"

    if not spec_path.exists():
        raise FileNotFoundError(f"OpenAPI spec missing for case '{case_id}' at {spec_path}")
    if not source_dir.exists():
        raise FileNotFoundError(f"Source directory missing for case '{case_id}' at {source_dir}")

    return spec_path, source_dir
