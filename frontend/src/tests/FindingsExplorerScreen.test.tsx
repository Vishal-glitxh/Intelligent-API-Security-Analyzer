import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import {
  AssistantResponseAttribution,
  FindingDescription,
  FindingEvidenceAndRemediation,
  FindingHeader,
} from '../components/findings/FindingsExplorerScreen';
import { mapCorrelatedFinding } from '../utils/findings';
import { CorrelatedFinding, Finding } from '../types/findings';

const baseFinding: Finding = {
  id: 'finding-1',
  rule_id: 'API-AUTH-001',
  title: 'Potential Missing Authentication Requirement (GET /items)',
  severity: 'HIGH',
  layer: 'SPEC',
  rationale: 'The OpenAPI operation has no declared security requirement.',
  evidence: [
    {
      kind: 'openapi_security',
      message: 'GET /items has no effective security requirement.',
    },
  ],
  remediation: 'Define and apply an appropriate security requirement.',
};

const correlatedFinding: CorrelatedFinding = {
  id: 'correlated-1',
  rule_id: 'CORR-AUTH-001',
  title: 'Correlated authentication divergence',
  severity: 'critical',
  confidence: 0.95,
  evidence: [{ kind: 'correlation', message: 'Correlation-level evidence.' }],
  correlation_state: 'CONTRADICTED',
  matched_endpoint: null,
  spec_findings: [
    {
      ...baseFinding,
      severity: 'high',
      evidence: [{ kind: 'spec', message: 'Child specification evidence.' }],
    },
  ],
  source_findings: [
    {
      ...baseFinding,
      severity: 'medium',
      evidence: [{ kind: 'source', message: 'Child source evidence.' }],
    },
  ],
  rationale: 'Correlation rationale.',
  remediation: 'Correlation remediation.',
};

function renderDetails(finding: Finding): string {
  return renderToStaticMarkup(
    <>
      <FindingHeader finding={finding} />
      <FindingDescription finding={finding} />
      <FindingEvidenceAndRemediation finding={finding} />
    </>,
  );
}

describe('Findings Explorer details', () => {
  it('uses rationale when a finding has no description', () => {
    const markup = renderDetails(baseFinding);

    expect(markup).toContain('The OpenAPI operation has no declared security requirement.');
    expect(markup).toContain('Vulnerability Description');
  });

  it('prefers a non-empty description over rationale', () => {
    const markup = renderDetails({
      ...baseFinding,
      description: 'The explicit description takes precedence.',
    });

    expect(markup).toContain('The explicit description takes precedence.');
    expect(markup).not.toContain('The OpenAPI operation has no declared security requirement.');
  });

  it('shows an empty state when neither description nor rationale is provided', () => {
    const markup = renderDetails({
      ...baseFinding,
      description: undefined,
      rationale: undefined,
    });

    expect(markup).toContain('No description available.');
  });

  it('treats whitespace-only description and rationale as empty', () => {
    const markup = renderDetails({
      ...baseFinding,
      description: '   ',
      rationale: '  ',
    });

    expect(markup).toContain('No description available.');
  });

  it('continues to render the title, severity, evidence, and remediation', () => {
    const markup = renderDetails(baseFinding);

    expect(markup).toContain('Potential Missing Authentication Requirement (GET /items)');
    expect(markup).toContain('HIGH');
    expect(markup).toContain('GET /items has no effective security requirement.');
    expect(markup).toContain('Define and apply an appropriate security requirement.');
  });

  it('prefers correlation-level severity, confidence, and evidence in the UI', () => {
    const finding = mapCorrelatedFinding(correlatedFinding);
    const markup = renderDetails(finding);

    expect(finding.severity).toBe('CRITICAL');
    expect(finding.confidence).toBe(0.95);
    expect(finding.evidence).toEqual(correlatedFinding.evidence);
    expect(markup).toContain('CRITICAL');
    expect(markup).toContain('0.95');
    expect(markup).toContain('Correlation-level evidence.');
    expect(markup).not.toContain('Child specification evidence.');
    expect(markup).not.toContain('Child source evidence.');
  });

  it('retains child-field fallbacks for legacy correlated records', () => {
    const legacyRecord: CorrelatedFinding = {
      ...correlatedFinding,
      severity: undefined,
      confidence: undefined,
      evidence: undefined,
    };

    const finding = mapCorrelatedFinding(legacyRecord);
    const markup = renderDetails(finding);

    expect(finding.severity).toBe('HIGH');
    expect(finding.confidence).toBeUndefined();
    expect(finding.evidence).toEqual(legacyRecord.spec_findings[0].evidence);
    expect(markup).toContain('Child specification evidence.');
    expect(markup).not.toContain('Confidence:');
  });

  it('falls back safely when parent and first child severities are malformed', () => {
    const malformedRecord = {
      ...correlatedFinding,
      severity: 7,
      spec_findings: [
        { ...correlatedFinding.spec_findings[0], severity: 'UNRECOGNIZED' },
      ],
      source_findings: [
        { ...correlatedFinding.source_findings[0], severity: 'low' },
      ],
    } as unknown as CorrelatedFinding;

    const finding = mapCorrelatedFinding(malformedRecord);
    const markup = renderDetails(finding);

    expect(finding.severity).toBe('LOW');
    expect(markup).toContain('LOW');
  });

  it('handles null optional confidence and evidence without crashing', () => {
    const malformedRecord = {
      ...correlatedFinding,
      confidence: null,
      evidence: null,
    } as unknown as CorrelatedFinding;

    const finding = mapCorrelatedFinding(malformedRecord);
    const markup = renderDetails(finding);

    expect(finding.confidence).toBeNull();
    expect(markup).not.toContain('Confidence:');
    expect(markup).toContain('Child specification evidence.');
  });
});

describe('Findings Explorer assistant attribution', () => {
  it('shows the policy refusal separately and labels deterministic claim evidence', () => {
    const markup = renderToStaticMarkup(
      <AssistantResponseAttribution
        response={{
          policy_refusal: "I can't reveal credentials or secrets.",
          claim_citations: [
            {
              claim_id: 'fallback-claim-1',
              text: 'Static analysis did not recognize an authentication guard.',
              source_ids: ['finding-1'],
              origin: 'deterministic_fallback',
              kind: 'scan_observation',
            },
            {
              claim_id: 'fallback-claim-2',
              text: "I can't reveal credentials or secrets.",
              source_ids: [],
              origin: 'deterministic_fallback',
              kind: 'policy_refusal',
            },
          ],
          sources: [
            {
              id: 'finding-1',
              title: 'Missing recognized authentication guard',
              source_type: 'scan_finding',
              citation: 'src/routes.py:42',
              excerpt: 'Static analysis did not recognize an authentication guard.',
              relevance: 1,
            },
          ],
        }}
      />,
    );

    expect(markup).toContain('Assistant policy refusal');
    expect(markup).toContain('I can&#x27;t reveal credentials or secrets.');
    expect(markup).toContain('Deterministic analysis');
    expect(markup).toContain('Missing recognized authentication guard');
    expect(markup).toContain('src/routes.py:42');
  });

  it('distinguishes model claim attribution and tolerates older responses without new fields', () => {
    const markup = renderToStaticMarkup(
      <>
        <AssistantResponseAttribution
          response={{
            claim_citations: [
              {
                claim_id: 'model-claim-1',
                text: 'Apply authorization checks to each resource.',
                source_ids: ['guide-1'],
                origin: 'local_model',
                kind: 'general_guidance',
              },
            ],
            sources: [
              {
                id: 'guide-1',
                title: 'Object-level authorization',
                source_type: 'security_knowledge',
                citation: 'OWASP API1',
                excerpt: 'Apply authorization checks to each resource.',
                relevance: 0.9,
              },
            ],
          }}
        />
        <AssistantResponseAttribution response={{ sources: [] }} />
      </>,
    );

    expect(markup).toContain('Local model');
    expect(markup).toContain('Object-level authorization');
    expect(markup).toContain('OWASP API1');
    expect(markup).toContain('general guidance');
  });

  it('renders a no-evidence abstention without inventing a source', () => {
    const markup = renderToStaticMarkup(
      <AssistantResponseAttribution
        response={{
          policy_refusal: "I can't reveal credentials or secrets.",
          claim_citations: [
            {
              claim_id: 'fallback-claim-1',
              text: 'No relevant scan evidence or security guidance matched that question.',
              source_ids: [],
              origin: 'deterministic_fallback',
              kind: 'abstention',
            },
          ],
          sources: [],
        }}
      />,
    );

    expect(markup).toContain('No relevant scan evidence');
    expect(markup).toContain('No retrieved source cited.');
  });
});
