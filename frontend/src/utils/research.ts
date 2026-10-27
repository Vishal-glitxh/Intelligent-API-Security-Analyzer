export function formatResearchPercent(value: number | null | undefined): string {
  return value === null || value === undefined ? 'N/A' : `${(value * 100).toFixed(1)}%`;
}

export function toResearchChartPercent(value: number | null | undefined): number | null {
  return value === null || value === undefined ? null : Number((value * 100).toFixed(1));
}
