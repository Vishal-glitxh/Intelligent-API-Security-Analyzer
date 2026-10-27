import { MatchedEndpoint } from './scan';

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingSeverity = Severity;
export type FindingCategory = string;
export type FindingConfidence = string | number;

export type CorrelationState = 'SUPPORTED' | 'CONTRADICTED' | 'COMPLEMENTARY' | 'INCONCLUSIVE';

export interface SourceLocation {
  file?: string;
  file_path?: string;
  line?: number;
  line_start?: number;
  column?: number;
  end_line?: number;
  end_column?: number;
  json_pointer?: string;
}

export type FindingLocation = SourceLocation;

export interface Evidence {
  kind: string;
  message: string;
  location?: SourceLocation | null;
}

export interface Finding {
  id?: string;
  rule_id: string;
  rule_version?: string;
  title: string;
  severity: Severity;
  category?: string;
  confidence?: number | string;
  rationale?: string;
  description?: string;
  remediation?: string;
  evidence?: Evidence[] | string | Record<string, any>;
  endpoint?: string;
  http_method?: string;
  cwe_id?: string;
  owasp_category?: string;
  layer?: 'SPEC' | 'SOURCE' | 'CORRELATED';
  location?: SourceLocation;
}

export interface CorrelatedFinding {
  id?: string;
  rule_id: string;
  rule_version?: string;
  title: string;
  category?: string;
  severity?: Severity;
  correlation_state: CorrelationState;
  matched_endpoint: MatchedEndpoint | null;
  spec_findings: Finding[];
  source_findings: Finding[];
  rationale: string;
  remediation: string;
}

export interface ScanFindingsResponse {
  scan_id: string;
  spec_only_findings: Finding[];
  source_only_findings: Finding[];
  correlated_findings: (CorrelatedFinding | Finding)[];
}

export interface ScanAssistantResponse {
  scan_id: string;
  answer: string;
  sources: Array<{
    id: string;
    title: string;
    source_type: string;
    citation: string;
    source_url?: string | null;
    license?: string | null;
    endpoint?: string | null;
    excerpt: string;
    relevance: number;
  }>;
  retrieval: string;
  external_network_used: boolean;
  notice: string;
  ai_status: 'Available' | 'Unavailable' | 'Disabled';
  model_name?: string | null;
  ai_used: boolean;
  ai_explanation?: string | null;
  recommendations: string[];
  /** IDs selected by the model and accepted against this response's retrieved sources. */
  cited_source_ids: string[];
}

export interface LocalAIStatus {
  status: 'Available' | 'Unavailable' | 'Disabled';
  model_name?: string | null;
  available_models: string[];
  embedding_model?: string | null;
  embedding_available: boolean;
  retrieval_available: boolean;
  message: string;
}
