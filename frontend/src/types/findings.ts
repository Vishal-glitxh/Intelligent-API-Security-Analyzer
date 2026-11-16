import { MatchedEndpoint } from './scan';

type CanonicalSeverity = 'HIGH' | 'MEDIUM' | 'LOW' | 'CRITICAL' | 'INFO';
export type Severity = CanonicalSeverity | Lowercase<CanonicalSeverity>;
export type FindingSeverity = Severity;
export type FindingCategory = string;
export type FindingConfidence = string | number;

export type CorrelationState = 'SUPPORTED' | 'CONTRADICTED' | 'COMPLEMENTARY' | 'INCONCLUSIVE';

export interface SourceLocation {
  file?: string | null;
  file_path?: string | null;
  line?: number | null;
  line_start?: number | null;
  column?: number | null;
  end_line?: number | null;
  end_column?: number | null;
  json_pointer?: string;
}

export type FindingLocation = SourceLocation;

export interface Evidence {
  kind: string;
  message: string;
  file?: string | null;
  line?: number | null;
  column?: number | null;
  end_line?: number | null;
  end_column?: number | null;
  source_hash?: string | null;
  provenance?: string | null;
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
  confidence?: number;
  evidence?: Evidence[];
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
    document_id?: string | null;
    chunk_id?: string | null;
    title: string;
    source_type: string;
    citation: string;
    source_location?: string | null;
    source_url?: string | null;
    license?: string | null;
    endpoint?: string | null;
    excerpt: string;
    relevance: number;
    retrieval_method?: string | null;
  }>;
  retrieval: string;
  ranking_policy: string;
  ranking_method: string;
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
  rag_index_status:
    | 'missing'
    | 'invalid'
    | 'ready'
    | 'stale_model'
    | 'stale_chunking'
    | 'lexical_only';
  rag_index_version?: string | null;
  rag_index_embedding_model?: string | null;
  rag_index_embedding_dimensions?: number | null;
  rag_index_document_count: number;
  rag_index_chunk_count: number;
}
