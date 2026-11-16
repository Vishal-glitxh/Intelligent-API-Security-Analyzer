import { CorrelatedFinding, Finding, Severity } from '../types/findings';

const VALID_SEVERITIES = ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL', 'INFO'] as const;

const normalizeSeverity = (value: unknown): Severity | undefined => {
  if (typeof value !== 'string') return undefined;

  const normalized = value.trim().toUpperCase();
  return VALID_SEVERITIES.includes(normalized as (typeof VALID_SEVERITIES)[number])
    ? (normalized as Severity)
    : undefined;
};

export const mapCorrelatedFinding = (finding: CorrelatedFinding | Finding): Finding => {
  const specFindings = 'spec_findings' in finding ? finding.spec_findings : [];
  const sourceFindings = 'source_findings' in finding ? finding.source_findings : [];
  const matchedEndpoint = 'matched_endpoint' in finding ? finding.matched_endpoint : null;

  return {
    id: finding.id || `${finding.rule_id}-${finding.title}`,
    rule_id: finding.rule_id,
    rule_version: finding.rule_version,
    title: finding.title,
    severity:
      normalizeSeverity(finding.severity) ??
      normalizeSeverity(specFindings[0]?.severity) ??
      normalizeSeverity(sourceFindings[0]?.severity) ??
      'MEDIUM',
    category: finding.category || specFindings[0]?.category || sourceFindings[0]?.category,
    confidence: finding.confidence,
    rationale: finding.rationale,
    remediation: finding.remediation,
    endpoint: matchedEndpoint?.spec_path,
    http_method: matchedEndpoint?.spec_method,
    layer: 'CORRELATED',
    evidence:
      finding.evidence || specFindings[0]?.evidence || sourceFindings[0]?.evidence,
  };
};
