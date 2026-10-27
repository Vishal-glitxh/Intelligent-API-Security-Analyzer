import { describe, expect, it } from 'vitest';
import { formatResearchPercent, toResearchChartPercent } from '../utils/research';

describe('research metric presentation', () => {
  it('preserves undefined metrics instead of presenting them as zero', () => {
    expect(formatResearchPercent(null)).toBe('N/A');
    expect(formatResearchPercent(undefined)).toBe('N/A');
    expect(toResearchChartPercent(null)).toBeNull();
  });

  it('formats real zero and non-zero metric values', () => {
    expect(formatResearchPercent(0)).toBe('0.0%');
    expect(formatResearchPercent(0.625)).toBe('62.5%');
    expect(toResearchChartPercent(0.625)).toBe(62.5);
  });
});
