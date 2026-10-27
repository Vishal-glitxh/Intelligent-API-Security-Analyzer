import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  Search, 
  FileCode, 
  AlertTriangle, 
  CheckCircle2, 
  X,
  RefreshCw,
  Code2,
  Sparkles,
  Send,
} from 'lucide-react';
import { api } from '../../services/api';
import { Finding } from '../../types/findings';
import { SeverityBadge, CategoryBadge, LayerBadge } from '../common/Badge';
import { redactSecrets } from '../../utils/redact';
import { ScanAssistantResponse } from '../../types/findings';

interface FindingsExplorerScreenProps {
  scanId: string;
}

export const FindingsExplorerScreen: React.FC<FindingsExplorerScreenProps> = ({ scanId }) => {
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLayer, setSelectedLayer] = useState<'ALL' | 'CORRELATED' | 'SPEC' | 'SOURCE'>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  
  // Selected detail item
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);
  const [assistantQuestion, setAssistantQuestion] = useState('');
  const [assistantResult, setAssistantResult] = useState<ScanAssistantResponse | null>(null);
  const [assistantLoading, setAssistantLoading] = useState(false);
  const [assistantError, setAssistantError] = useState<string | null>(null);

  const askAssistant = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (assistantQuestion.trim().length < 3 || assistantLoading) return;
    setAssistantLoading(true);
    setAssistantError(null);
    try {
      setAssistantResult(await api.askScanAssistant(scanId, assistantQuestion.trim()));
    } catch (err: any) {
      setAssistantError(err.message || 'The scan assistant could not answer right now.');
    } finally {
      setAssistantLoading(false);
    }
  };

  const fetchFindings = useCallback(async () => {
    try {
      const data = await api.getScanFindings(scanId);
      
      const spec: Finding[] = (data.spec_only_findings || []).map((f) => ({ ...f, layer: 'SPEC' as const }));
      const source: Finding[] = (data.source_only_findings || []).map((f) => ({ ...f, layer: 'SOURCE' as const }));
      const correlated: Finding[] = (data.correlated_findings || []).map((f: any) => ({
        id: f.id || `${f.rule_id}-${f.title}`,
        rule_id: f.rule_id,
        rule_version: f.rule_version,
        title: f.title,
        severity: (f.severity || f.spec_findings?.[0]?.severity || f.source_findings?.[0]?.severity || 'MEDIUM') as any,
        category: f.category || f.spec_findings?.[0]?.category || f.source_findings?.[0]?.category,
        confidence: f.confidence,
        rationale: f.rationale,
        remediation: f.remediation,
        endpoint: f.matched_endpoint?.spec_path,
        http_method: f.matched_endpoint?.spec_method,
        layer: 'CORRELATED' as const,
        evidence: f.evidence || f.spec_findings?.[0]?.evidence || f.source_findings?.[0]?.evidence,
      }));

      const combined: Finding[] = [...correlated, ...spec, ...source];
      setAllFindings(combined);
      if (combined.length > 0) {
        setActiveFinding(combined[0]);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load security findings.');
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect -- This starts an API request; its state updates run after the request settles.
    void fetchFindings();
  }, [fetchFindings]);

  // Unique categories for filter dropdown
  const categories = useMemo(() => {
    const set = new Set<string>();
    allFindings.forEach((f) => {
      if (f.category) set.add(f.category);
    });
    return Array.from(set);
  }, [allFindings]);

  // Filtered dataset
  const filteredFindings = useMemo(() => {
    return allFindings.filter((finding) => {
      // Layer filter
      if (selectedLayer !== 'ALL' && finding.layer !== selectedLayer) {
        return false;
      }

      // Severity filter
      if (selectedSeverity !== 'ALL' && finding.severity !== selectedSeverity) {
        return false;
      }

      // Category filter
      if (selectedCategory !== 'ALL' && finding.category !== selectedCategory) {
        return false;
      }

      // Search term (rule_id, title, description, endpoint)
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase();
        const matchesRule = finding.rule_id?.toLowerCase().includes(query);
        const matchesTitle = finding.title?.toLowerCase().includes(query);
        const matchesDesc = finding.description?.toLowerCase().includes(query);
        const matchesEndpoint = finding.endpoint?.toLowerCase().includes(query);
        const matchesCwe = finding.cwe_id?.toLowerCase().includes(query);
        if (!matchesRule && !matchesTitle && !matchesDesc && !matchesEndpoint && !matchesCwe) {
          return false;
        }
      }

      return true;
    });
  }, [allFindings, selectedLayer, selectedSeverity, selectedCategory, searchTerm]);

  return (
    <div className="space-y-4">
      <section className="rounded-xl border border-teal-900/60 bg-gradient-to-br from-slate-900 via-slate-900 to-teal-950/40 p-4 md:p-5">
        <div className="flex items-start gap-3">
          <div className="rounded-lg border border-teal-800/70 bg-teal-950/70 p-2 text-teal-300">
            <Sparkles className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <h2 className="text-sm font-semibold text-slate-100">Evidence assistant</h2>
              <span className="rounded-full border border-slate-700 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-400">Keyless · local retrieval</span>
            </div>
            <p className="mt-1 text-xs leading-5 text-slate-400">Ask about this scan. Answers retrieve your findings and endpoint mappings alongside bundled API security guidance.</p>
          </div>
        </div>
        <form onSubmit={askAssistant} className="mt-4 flex flex-col gap-2 sm:flex-row">
          <input
            value={assistantQuestion}
            onChange={(event) => setAssistantQuestion(event.target.value)}
            maxLength={500}
            placeholder="e.g. Which endpoints lack object ownership checks?"
            className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-teal-600 focus:outline-none"
          />
          <button
            type="submit"
            disabled={assistantQuestion.trim().length < 3 || assistantLoading}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-teal-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Send className="h-3.5 w-3.5" />
            {assistantLoading ? 'Searching…' : 'Ask'}
          </button>
        </form>
        {assistantError && <p role="alert" className="mt-3 text-xs text-rose-300">{assistantError}</p>}
        {assistantResult && (
          <div className="mt-4 space-y-3 border-t border-slate-800 pt-4">
            <p className="text-sm leading-6 text-slate-200">{assistantResult.answer}</p>
            {assistantResult.ai_used && assistantResult.ai_explanation && (
              <div className="rounded-lg border border-violet-900/60 bg-violet-950/20 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-violet-300">
                  Local model explanation · {assistantResult.model_name}
                </p>
                <p className="mt-2 text-sm leading-6 text-slate-200">{assistantResult.ai_explanation}</p>
                {assistantResult.recommendations.length > 0 && (
                  <div className="mt-3">
                    <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">Suggested next steps · verify against evidence</p>
                    <ul className="mt-1 list-disc space-y-1 pl-5 text-xs text-slate-300">
                      {assistantResult.recommendations.map((recommendation, index) => (
                        <li key={`${index}-${recommendation}`}>{recommendation}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
            {assistantResult.sources.length > 0 && (
              <section aria-label="Retrieved evidence sources" className="space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                  Retrieved sources · {assistantResult.sources.length}
                </p>
                <div className="grid gap-2 md:grid-cols-2">
                  {assistantResult.sources.map((source) => {
                    const citedByModel = assistantResult.cited_source_ids.includes(source.id);
                    return (
                      <article
                        key={source.id}
                        className={`rounded-lg border p-3 ${citedByModel ? 'border-violet-800/70 bg-violet-950/20' : 'border-slate-800 bg-slate-950/60'}`}
                      >
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <p className="text-xs font-semibold text-teal-200">{source.title}</p>
                          <span className={`rounded-full border px-2 py-0.5 text-[9px] font-medium ${citedByModel ? 'border-violet-800 text-violet-300' : 'border-slate-700 text-slate-500'}`}>
                            {citedByModel ? 'Cited by model' : 'Retrieved context'}
                          </span>
                        </div>
                        <p className="mt-1 text-[11px] leading-5 text-slate-400">{redactSecrets(source.excerpt)}</p>
                        <p className="mt-2 text-[10px] text-slate-500">
                          Source: {source.source_url ? (
                            <a href={source.source_url} target="_blank" rel="noreferrer" className="underline decoration-slate-700 underline-offset-2 hover:text-slate-300">
                              {source.citation}
                            </a>
                          ) : source.citation}
                          {source.license ? ` · ${source.license}` : ''}
                        </p>
                      </article>
                    );
                  })}
                </div>
              </section>
            )}
            <p className="text-[10px] text-slate-500">
              Local AI: {assistantResult.ai_status}{assistantResult.model_name ? ` · ${assistantResult.model_name}` : ''} · {assistantResult.notice}
            </p>
          </div>
        )}
      </section>

      {/* Top Filter & Search Bar */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Search input */}
          <div className="relative flex-1">
            <Search className="h-4 w-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter by rule ID, title, endpoint, or CWE..."
              className="w-full bg-slate-950 border border-slate-800 focus:border-teal-500 focus:ring-1 focus:ring-teal-500 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 transition-colors font-mono"
            />
            {searchTerm && (
              <button 
                onClick={() => setSearchTerm('')} 
                className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {/* Quick Refresh */}
          <button
            onClick={fetchFindings}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium rounded-md transition-colors shrink-0"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {/* Dropdowns Row */}
        <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-slate-800/80 text-xs">
          {/* Layer tabs */}
          <div className="flex items-center bg-slate-950 p-0.5 rounded border border-slate-800 text-[11px] font-mono">
            {(['ALL', 'CORRELATED', 'SPEC', 'SOURCE'] as const).map((layer) => (
              <button
                key={layer}
                onClick={() => setSelectedLayer(layer)}
                className={`px-2.5 py-1 rounded transition-colors ${
                  selectedLayer === layer
                    ? 'bg-teal-500/20 text-teal-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {layer}
              </button>
            ))}
          </div>

          {/* Severity selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500 font-mono text-[11px]">Severity:</span>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300 text-xs font-mono focus:border-teal-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
          </div>

          {/* Category selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500 font-mono text-[11px]">Category:</span>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-300 text-xs font-mono focus:border-teal-500"
            >
              <option value="ALL">All Categories</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>

          {/* Count Badge */}
          <div className="ml-auto text-[11px] font-mono text-slate-400">
            Showing <span className="text-teal-400 font-semibold">{filteredFindings.length}</span> of {allFindings.length} findings
          </div>
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="p-16 text-center flex flex-col items-center justify-center gap-3">
          <RefreshCw className="h-6 w-6 text-teal-400 animate-spin" />
          <p className="text-xs text-slate-400 font-mono">Loading findings for #{scanId.slice(0, 8)}...</p>
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div className="p-8 bg-slate-900 border border-slate-800 rounded-lg text-center flex flex-col items-center justify-center gap-3">
          <AlertTriangle className="h-6 w-6 text-rose-400" />
          <p className="text-sm font-semibold text-slate-200">Unable to load findings</p>
          <p className="text-xs text-slate-400 max-w-md font-mono">{error}</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && filteredFindings.length === 0 && (
        <div className="p-12 bg-slate-900 border border-slate-800 rounded-lg text-center flex flex-col items-center justify-center gap-2">
          <CheckCircle2 className="h-8 w-8 text-emerald-400" />
          <p className="text-sm font-semibold text-slate-200">No findings match criteria</p>
          <p className="text-xs text-slate-400">
            {allFindings.length === 0 
              ? 'This scan completed with zero security findings recorded across all layers.'
              : 'Try clearing or relaxing your active search and filter thresholds.'}
          </p>
        </div>
      )}

      {/* Two-Pane Layout: List on Left, Detail on Right */}
      {!loading && !error && filteredFindings.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Findings List (5 cols) */}
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col max-h-[750px]">
            <div className="p-3 border-b border-slate-800 bg-slate-950/40 text-[11px] font-mono uppercase text-slate-400 flex justify-between">
              <span>Security Issue</span>
              <span>Layer & Severity</span>
            </div>
            <div className="overflow-y-auto divide-y divide-slate-800/60 flex-1">
              {filteredFindings.map((finding) => {
                const isSelected = activeFinding?.id === finding.id;
                return (
                  <div
                    key={finding.id}
                    onClick={() => setActiveFinding(finding)}
                    className={`p-3 cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-teal-500/10 border-l-2 border-teal-400'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1 min-w-0">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-teal-300 border border-slate-700">
                            {finding.rule_id}
                          </span>
                          {finding.cwe_id && (
                            <span className="text-[10px] font-mono text-slate-400">
                              {finding.cwe_id}
                            </span>
                          )}
                        </div>
                        <h4 className="text-xs font-semibold text-slate-200 truncate" title={finding.title}>
                          {finding.title}
                        </h4>
                        {finding.endpoint && (
                          <div className="text-[11px] font-mono text-slate-400 truncate flex items-center gap-1">
                            {finding.http_method && (
                              <span className="text-slate-300 font-bold">{finding.http_method}</span>
                            )}
                            <span>{finding.endpoint}</span>
                          </div>
                        )}
                      </div>

                      <div className="flex flex-col items-end gap-1 shrink-0">
                        <SeverityBadge severity={finding.severity} />
                        <LayerBadge layer={finding.layer} />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Finding Detail Pane (7 cols) */}
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col space-y-5 max-h-[750px] overflow-y-auto">
            {activeFinding ? (
              <>
                {/* Header info */}
                <div className="space-y-2 border-b border-slate-800 pb-4">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={activeFinding.severity} />
                      <LayerBadge layer={activeFinding.layer} />
                      {activeFinding.category && <CategoryBadge category={activeFinding.category} />}
                    </div>
                    <span className="text-xs font-mono text-slate-500">
                      ID: {activeFinding.id}
                    </span>
                  </div>

                  <h3 className="text-base font-semibold text-slate-100">
                    {activeFinding.title}
                  </h3>

                  <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-400 pt-1">
                    <div>
                      Rule: <span className="text-teal-400">{activeFinding.rule_id}</span>
                    </div>
                    {activeFinding.cwe_id && (
                      <div>
                        CWE: <span className="text-slate-300">{activeFinding.cwe_id}</span>
                      </div>
                    )}
                    {activeFinding.confidence !== undefined && activeFinding.confidence !== null && (
                      <div>
                        Confidence: <span className="text-slate-300">{activeFinding.confidence}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Endpoint & Method Location */}
                {(activeFinding.endpoint || activeFinding.http_method) && (
                  <div className="bg-slate-950 border border-slate-800 p-3 rounded-md space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">
                      Target Endpoint Contract
                    </span>
                    <div className="text-xs font-mono text-slate-200 flex items-center gap-2">
                      {activeFinding.http_method && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-teal-300 font-bold text-[10px]">
                          {activeFinding.http_method}
                        </span>
                      )}
                      <span>{activeFinding.endpoint}</span>
                    </div>
                  </div>
                )}

                {/* Description */}
                <div>
                  <h4 className="text-xs font-mono uppercase text-slate-400 mb-1.5 flex items-center gap-1.5">
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                    <span>Vulnerability Description</span>
                  </h4>
                  <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/40 p-3 rounded border border-slate-800/80">
                    {activeFinding.description}
                  </p>
                </div>

                {/* Source or Specification Location */}
                {activeFinding.location && (
                  <div>
                    <h4 className="text-xs font-mono uppercase text-slate-400 mb-1.5 flex items-center gap-1.5">
                      <FileCode className="h-3.5 w-3.5 text-teal-400" />
                      <span>Detected Location</span>
                    </h4>
                    <div className="bg-slate-950 p-3 rounded border border-slate-800 text-xs font-mono text-slate-300 space-y-1">
                      {(activeFinding.location.file_path || activeFinding.location.file) && (
                        <div>
                          <span className="text-slate-500">File: </span>
                          <span className="text-teal-300">
                            {activeFinding.location.file_path || activeFinding.location.file}
                          </span>
                        </div>
                      )}
                      {(activeFinding.location.line_start !== undefined || activeFinding.location.line !== undefined) && (
                        <div>
                          <span className="text-slate-500">Lines: </span>
                          <span>
                            {activeFinding.location.line_start ?? activeFinding.location.line}
                            {activeFinding.location.end_line &&
                            activeFinding.location.end_line !== (activeFinding.location.line_start ?? activeFinding.location.line)
                              ? ` - ${activeFinding.location.end_line}`
                              : ''}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Evidence (with secret redaction) */}
                {activeFinding.evidence && (
                  <div>
                    <h4 className="text-xs font-mono uppercase text-slate-400 mb-1.5 flex items-center gap-1.5">
                      <Code2 className="h-3.5 w-3.5 text-cyan-400" />
                      <span>Security Evidence</span>
                      <span className="text-[10px] text-slate-500 ml-auto font-normal">
                        (Secrets redacted automatically)
                      </span>
                    </h4>
                    <div className="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto max-h-48">
                      <pre className="whitespace-pre-wrap">
                        {typeof activeFinding.evidence === 'string'
                          ? redactSecrets(activeFinding.evidence)
                          : redactSecrets(JSON.stringify(activeFinding.evidence, null, 2))}
                      </pre>
                    </div>
                  </div>
                )}

                {/* Remediation guidance */}
                {activeFinding.remediation && (
                  <div>
                    <h4 className="text-xs font-mono uppercase text-slate-400 mb-1.5 flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                      <span>Remediation Guidance</span>
                    </h4>
                    <div className="bg-emerald-950/20 border border-emerald-500/20 p-3 rounded text-xs text-emerald-300/90 leading-relaxed">
                      {activeFinding.remediation}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="p-12 text-center text-slate-500 text-xs">
                Select a finding from the list on the left to inspect vulnerability details.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
