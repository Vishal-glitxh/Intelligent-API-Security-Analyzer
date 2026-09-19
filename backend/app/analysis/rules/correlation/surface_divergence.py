from collections.abc import Sequence

from app.analysis.context import AnalysisContext
from app.analysis.correlation.models import (
    AnalysisLayer,
    CorrelatedFinding,
    CorrelationState,
    EndpointMatchState,
    MatchedEndpointPair,
)
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.correlation.base import CorrelationRule


class SurfaceDivergenceCorrelationRule(CorrelationRule):
    """CORR-SURF-001: Detects API surface discrepancies between specification and source.

    Identifies:
    1. Potential Shadow Endpoints: Exists in source code, missing from OpenAPI specification.
    2. Potential Zombie Endpoints: Documented in spec, missing from source implementation.

    Uses strictly qualified language; does not assert definitive exploitability or obsolescence.
    """

    rule_id = "CORR-SURF-001"
    rule_version = "1.0.0"

    def correlate(
        self,
        context: AnalysisContext,
        matched_pairs: Sequence[MatchedEndpointPair],
        spec_findings: Sequence[Finding],
        source_findings: Sequence[Finding],
    ) -> list[CorrelatedFinding]:
        findings: list[CorrelatedFinding] = []

        # 1. Identify Potential Zombie Endpoints (in spec, no source handler)
        for pair in matched_pairs:
            if pair.match_state == EndpointMatchState.NO_MATCH and pair.spec_operation:
                op = pair.spec_operation
                method = op.method.upper()
                ev = Evidence(
                    kind="unmatched_spec_endpoint",
                    message=(
                        f"Specification operation {method} {op.path} has no corresponding "
                        "source code handler."
                    ),
                    file=op.location.file if op.location else None,
                    line=op.location.line if op.location else None,
                    column=op.location.column if op.location else None,
                    provenance=f"spec:{op.path}#{op.method}",
                )

                findings.append(
                    CorrelatedFinding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            f"Potential Zombie Endpoint: Documented Without Handler "
                            f"({method} {op.path})"
                        ),
                        severity=Severity.LOW,
                        confidence=0.85,
                        rationale=(
                            f"The OpenAPI contract documents endpoint {method} {op.path}, but "
                            "static source analysis found no matching route handler in the "
                            "analyzed repository. This may represent a deprecated route, planned "
                            "feature, phantom endpoint, or dynamic route dispatch. Requires "
                            "architectural verification."
                        ),
                        remediation=(
                            f"Verify if operation {method} {op.path} is implemented elsewhere "
                            "(e.g. separate service or gateway). If obsolete, remove it from the "
                            "OpenAPI specification."
                        ),
                        evidence=(ev,),
                        correlation_state=CorrelationState.CONTRADICTED,
                        layer=AnalysisLayer.CORRELATED,
                        matched_endpoint=pair,
                        spec_findings=(),
                        source_findings=(),
                        evidence_pairs=(),
                        divergence_details="Operation exists in spec but not in source code.",
                    )
                )

        # 2. Identify Potential Shadow Endpoints (in source, no spec operation)
        # Find source endpoints that were never matched
        matched_source_paths: set[tuple[str, str]] = {
            (p.source_method.upper(), p.source_path)
            for p in matched_pairs
            if p.source_method and p.source_path
        }

        if context.source and context.source.endpoints:
            for s_ep in context.source.endpoints:
                key = (s_ep.method.upper(), s_ep.path)
                if key not in matched_source_paths:
                    ev = Evidence(
                        kind="unmatched_source_endpoint",
                        message=(
                            f"Source route handler '{s_ep.handler_name}' "
                            f"({s_ep.method.upper()} {s_ep.path}) is not documented in spec."
                        ),
                        file=s_ep.location.file if s_ep.location else s_ep.file_path,
                        line=s_ep.location.line if s_ep.location else None,
                        column=s_ep.location.column if s_ep.location else None,
                        provenance=f"source:{s_ep.file_path}:{s_ep.handler_name}",
                    )

                    pair = MatchedEndpointPair(
                        spec_path="",
                        spec_method="",
                        source_path=s_ep.path,
                        source_method=s_ep.method.upper(),
                        match_state=EndpointMatchState.NO_MATCH,
                        canonical_matching_path=s_ep.path,
                        spec_operation=None,
                        source_endpoint=s_ep,
                        spec_operation_id=None,
                        source_handler_name=s_ep.handler_name,
                        match_rationale="Source endpoint lacks corresponding spec operation.",
                        spec_location=None,
                        source_location=s_ep.location,
                    )

                    findings.append(
                        CorrelatedFinding(
                            rule_id=self.rule_id,
                            rule_version=self.rule_version,
                            title=(
                                f"Potential Shadow Endpoint: Handler Undocumented in Spec "
                                f"({s_ep.method.upper()} {s_ep.path})"
                            ),
                            severity=Severity.MEDIUM,
                            confidence=0.90,
                            rationale=(
                                f"Source code defines an active handler '{s_ep.handler_name}' "
                                f"for {s_ep.method.upper()} {s_ep.path}, but this endpoint is "
                                "completely absent from the OpenAPI specification. Undocumented "
                                "endpoints risk bypassing security audits, automated testing, and "
                                "API gateway rate limiting. Requires verification."
                            ),
                            remediation=(
                                f"Document {s_ep.method.upper()} {s_ep.path} in OpenAPI, or remove "
                                "the route handler if it is obsolete or private."
                            ),
                            evidence=(ev,),
                            correlation_state=CorrelationState.CONTRADICTED,
                            layer=AnalysisLayer.CORRELATED,
                            matched_endpoint=pair,
                            spec_findings=(),
                            source_findings=(),
                            evidence_pairs=(),
                            divergence_details="Route exists in source but not in specification.",
                        )
                    )

        return findings
