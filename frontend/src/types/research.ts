export interface MetricPopulation {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  fpr: number | null;
  fnr: number | null;
  undefined_reasons?: Record<string, string>;
}

export interface ModeMetrics {
  overall: MetricPopulation;
  categories: Record<string, MetricPopulation>;
}

export interface BenchmarkMetricsReport {
  experiment_id: string;
  dataset_version: string;
  modes: {
    SPEC_ONLY: ModeMetrics;
    SOURCE_ONLY: ModeMetrics;
    CORRELATED: ModeMetrics;
  };
}

export interface ConfidenceInterval {
  metric: string;
  mode: string;
  estimate: number | null;
  lower: number | null;
  upper: number | null;
  confidence_level: number;
  method: string;
}

export interface ModeComparison {
  comparison: string;
  metric: string;
  difference: number;
  ci_lower: number;
  ci_upper: number;
  p_value?: number;
  significant: boolean;
}

export interface ErrorTaxonomyItem {
  id: string;
  category: string;
  error_type: string;
  frequency: number;
  primary_driver: string;
  impact_summary: string;
}

export interface ResearchBenchmarksData {
  baseline: BenchmarkMetricsReport | null;
  external: BenchmarkMetricsReport | null;
  combined?: BenchmarkMetricsReport | null;
  phase7?: {
    confidence_intervals?: { intervals: ConfidenceInterval[] } | ConfidenceInterval[] | null;
    mode_comparisons?: { comparisons: ModeComparison[] } | ModeComparison[] | null;
    error_taxonomy?: { taxonomy: ErrorTaxonomyItem[] } | ErrorTaxonomyItem[] | null;
  } | null;
}
