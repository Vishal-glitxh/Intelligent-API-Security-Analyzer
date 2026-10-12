import { describe, it, expect } from 'vitest';
import { fallbackBenchmarkData } from '../services/benchmarkData';

describe('Research Benchmark Schema Integrity', () => {
  it('contains baseline 24-case benchmark with all 3 detection modes', () => {
    const baseline = fallbackBenchmarkData.baseline;
    expect(baseline).not.toBeNull();
    expect(baseline?.modes.SPEC_ONLY).toBeDefined();
    expect(baseline?.modes.SOURCE_ONLY).toBeDefined();
    expect(baseline?.modes.CORRELATED).toBeDefined();

    // Verify baseline correlated mode metrics
    const correlated = baseline!.modes.CORRELATED.overall;
    expect(correlated.tp).toBe(5);
    expect(correlated.fp).toBe(1);
    expect(correlated.precision).toBeCloseTo(0.8333, 3);
    expect(correlated.recall).toBeCloseTo(0.625, 3);
  });

  it('contains external VAmPI benchmark with transparent Connexion architecture results', () => {
    const external = fallbackBenchmarkData.external;
    expect(external).not.toBeNull();
    expect(external?.dataset_version).toBe('7.3.0');

    // Confirm that source and correlated have 0 TP due to Connexion swagger routing
    const sourceOverall = external!.modes.SOURCE_ONLY.overall;
    expect(sourceOverall.tp).toBe(0);
    expect(sourceOverall.fn).toBe(7);

    const specOverall = external!.modes.SPEC_ONLY.overall;
    expect(specOverall.tp).toBe(4);
    expect(specOverall.fp).toBe(2);
  });

  it('includes Phase 7 confidence intervals with Wilson score and bootstrap methods', () => {
    const cis = fallbackBenchmarkData.phase7?.confidence_intervals;
    expect(Array.isArray(cis)).toBe(true);
    expect((cis as any[]).length).toBeGreaterThan(0);

    const correlatedPrec = (cis as any[]).find(
      (c) => c.metric === 'precision' && c.mode === 'CORRELATED'
    );
    expect(correlatedPrec).toBeDefined();
    expect(correlatedPrec.estimate).toBeCloseTo(0.8333, 3);
    expect(correlatedPrec.lower).toBeLessThan(correlatedPrec.estimate);
    expect(correlatedPrec.upper).toBeGreaterThan(correlatedPrec.estimate);
  });
});
