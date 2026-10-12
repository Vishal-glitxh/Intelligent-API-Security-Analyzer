export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export interface Scan {
  scan_id: string;
  id?: string;
  status: ScanStatus;
  project_name: string;
  spec_filename?: string;
  source_filename?: string;
  spec_hash?: string | null;
  source_hash?: string | null;
  engine_version?: string;
  rule_set_version?: string;
  config_version?: string;
  error_message?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  client_id?: string;
  metrics?: {
    spec_endpoints_count?: number;
    source_endpoints_count?: number;
    matched_endpoints_count?: number;
    total_findings?: number;
    execution_time_ms?: number;
  };
}

export type ScanResponse = Scan;

export interface ScanCreateResponse {
  scan_id: string;
  id?: string;
  status: ScanStatus;
  project_name: string;
  created_at: string;
}

export interface MatchedEndpoint {
  spec_path: string;
  spec_method: string;
  source_path: string | null;
  source_method: string | null;
  match_tier: string;
  rationale: string;
  similarity_score?: number;
}

export interface MetricsSummary {
  total_spec_endpoints?: number;
  total_source_endpoints?: number;
  spec_only_findings_count?: number;
  source_only_findings_count?: number;
  correlated_findings_count?: number;
  matched_endpoints_count?: number;
  [key: string]: unknown;
}

export interface ScanResultsResponse {
  scan_id: string;
  metrics_summary?: MetricsSummary;
  summary?: {
    spec_endpoints_count?: number;
    source_endpoints_count?: number;
    matched_endpoints_count?: number;
    total_findings?: number;
  };
  matched_endpoints: MatchedEndpoint[];
}
