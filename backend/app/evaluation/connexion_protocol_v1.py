"""Fixture-backed, separately versioned evaluation of contract-assisted Connexion mapping."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from app.analysis.context import NormalizedEndpoint, NormalizedOpenAPI, NormalizedOperation
from app.analysis.source import load_source_from_memory, normalize_source_tree
from app.analysis.source.connexion import has_connexion_registration
from app.analysis.source.parser import parse_source_file

PROTOCOL_VERSION = "connexion-contract-assisted-v1"
DEFAULT_FIXTURE_FILE = (
    Path(__file__).resolve().parents[3] / "evaluation/connexion_protocol/v1/cases.json"
)


def _load_cases(fixture_file: Path) -> list[dict[str, Any]]:
    value = json.loads(fixture_file.read_text(encoding="utf-8"))
    raw_cases = value.get("cases")
    if value.get("protocol_version") != PROTOCOL_VERSION or not isinstance(raw_cases, list):
        raise ValueError("Invalid Connexion protocol fixture manifest")
    return cast(list[dict[str, Any]], raw_cases)


def evaluate_connexion_protocol(fixture_file: Path = DEFAULT_FIXTURE_FILE) -> dict[str, Any]:
    """Evaluate structural registration, route mappings, and source-line provenance."""
    manifest_bytes = fixture_file.read_bytes()
    cases = _load_cases(fixture_file)
    details: list[dict[str, Any]] = []
    registration = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    mapping_tp = mapping_fp = mapping_fn = 0
    provenance_pass = provenance_total = 0
    failure_counts: dict[str, int] = {}

    for case in cases:
        source_files = case["source_files"]
        loaded = load_source_from_memory(source_files)
        parsed_modules = [
            parse_source_file(file.content, file.relative_path, file.content_hash)
            for file in loaded.files
        ]
        actual_registered = any(has_connexion_registration(module) for module in parsed_modules)
        expected_registered = bool(case["expected_registration"])
        if expected_registered and actual_registered:
            registration["tp"] += 1
        elif expected_registered:
            registration["fn"] += 1
            failure_counts["missed_registration"] = failure_counts.get("missed_registration", 0) + 1
        elif actual_registered:
            registration["fp"] += 1
            failure_counts["false_registration"] = failure_counts.get("false_registration", 0) + 1
        else:
            registration["tn"] += 1

        operations = tuple(
            NormalizedOperation(
                method=entry["method"],
                path=entry["path"],
                operation_id=entry["operation_id"],
            )
            for entry in case["operations"]
        )
        specification = NormalizedOpenAPI(
            endpoints=tuple(
                NormalizedEndpoint(
                    path=path,
                    operations=tuple(
                        operation for operation in operations if operation.path == path
                    ),
                )
                for path in sorted({operation.path for operation in operations})
            )
        )
        tree = normalize_source_tree(loaded, specification=specification)
        observed = {
            (endpoint.method.lower(), endpoint.path, endpoint.handler_name, endpoint.file_path)
            for endpoint in tree.endpoints
            if endpoint.framework == "connexion"
        }
        expected = {
            (entry["method"].lower(), entry["path"], entry["handler"], entry["source_file"])
            for entry in case["expected_mappings"]
        }
        mapping_tp += len(observed & expected)
        mapping_fp += len(observed - expected)
        mapping_fn += len(expected - observed)
        if observed - expected:
            failure_counts["false_mapping"] = failure_counts.get("false_mapping", 0) + len(
                observed - expected
            )
        if expected - observed:
            failure_counts["missed_mapping"] = failure_counts.get("missed_mapping", 0) + len(
                expected - observed
            )

        expected_locations = {
            (
                entry["method"].lower(),
                entry["path"],
                entry["handler"],
                entry["source_file"],
            ): entry["line"]
            for entry in case["expected_mappings"]
        }
        observed_endpoints = {
            (
                endpoint.method.lower(),
                endpoint.path,
                endpoint.handler_name,
                endpoint.file_path,
            ): endpoint
            for endpoint in tree.endpoints
            if endpoint.framework == "connexion"
        }
        case_provenance_ok = True
        for key in sorted(observed & expected):
            provenance_total += 1
            endpoint = observed_endpoints[key]
            valid = (
                endpoint.location is not None
                and endpoint.location.file == key[3]
                and endpoint.location.line == expected_locations[key]
            )
            case_provenance_ok &= valid
            provenance_pass += int(valid)
            if not valid:
                failure_counts["wrong_evidence_provenance"] = (
                    failure_counts.get("wrong_evidence_provenance", 0) + 1
                )

        details.append(
            {
                "case_id": case["case_id"],
                "expected_registration": expected_registered,
                "observed_registration": actual_registered,
                "expected_mappings": [list(item) for item in sorted(expected)],
                "observed_mappings": [list(item) for item in sorted(observed)],
                "provenance_valid": case_provenance_ok,
            }
        )

    mapping_precision_denominator = mapping_tp + mapping_fp
    mapping_recall_denominator = mapping_tp + mapping_fn
    return {
        "protocol_version": PROTOCOL_VERSION,
        "fixture_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "case_count": len(cases),
        "registration": {
            **registration,
            "precision": registration["tp"] / (registration["tp"] + registration["fp"])
            if registration["tp"] + registration["fp"]
            else None,
            "recall": registration["tp"] / (registration["tp"] + registration["fn"])
            if registration["tp"] + registration["fn"]
            else None,
        },
        "mapping": {
            "tp": mapping_tp,
            "fp": mapping_fp,
            "fn": mapping_fn,
            "precision": (
                mapping_tp / mapping_precision_denominator
                if mapping_precision_denominator
                else None
            ),
            "recall": (
                mapping_tp / mapping_recall_denominator if mapping_recall_denominator else None
            ),
        },
        "evidence_provenance": {
            "passed": provenance_pass,
            "total": provenance_total,
            "accuracy": provenance_pass / provenance_total if provenance_total else None,
        },
        "failure_categories": dict(sorted(failure_counts.items())),
        "cases": details,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Run {PROTOCOL_VERSION}")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURE_FILE)
    args = parser.parse_args()
    result = evaluate_connexion_protocol(args.fixtures)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"{PROTOCOL_VERSION}: {args.output_dir / 'results.json'}")


if __name__ == "__main__":
    main()
