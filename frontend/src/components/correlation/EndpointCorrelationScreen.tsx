import React, { useState, useEffect, useMemo } from 'react';
import { 
  GitCompare, 
  Search, 
  Filter, 
  CheckCircle2, 
  AlertCircle, 
  RefreshCw, 
  ArrowRight, 
  FileCode, 
  Layers, 
  Info,
  ExternalLink,
  Code2
} from 'lucide-react';
import { api } from '../../services/api';
import { MatchedEndpoint, ScanResultsResponse } from '../../types/scan';
import { TierBadge } from '../common/Badge';

interface EndpointCorrelationScreenProps {
  scanId: string;
  onNavigate: (screen: any, scanId?: string) => void;
}

export const EndpointCorrelationScreen: React.FC<EndpointCorrelationScreenProps> = ({
  scanId,
  onNavigate
}) => {
  const [results, setResults] = useState<ScanResultsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchPath, setSearchPath] = useState('');
  const [tierFilter, setTierFilter] = useState<string>('ALL');
  
  // Selected detail
  const [selectedEndpoint, setSelectedEndpoint] = useState<MatchedEndpoint | null>(null);

  const fetchResults = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getScanResults(scanId);
      setResults(data);
      if (data.matched_endpoints && data.matched_endpoints.length > 0) {
        setSelectedEndpoint(data.matched_endpoints[0]);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load endpoint correlation matrix.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResults();
  }, [scanId]);

  const endpoints = results?.matched_endpoints || [];

  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((ep) => {
      if (tierFilter !== 'ALL') {
        const tierNorm = ep.match_tier.toUpperCase();
        if (tierFilter === 'EXACT' && !tierNorm.includes('EXACT') && !tierNorm.includes('TIER_1')) {
          return false;
        }
        if (tierFilter === 'PARAMETERIZED' && !tierNorm.includes('PARAM') && !tierNorm.includes('TIER_2')) {
          return false;
        }
        if (tierFilter === 'NORMALIZED' && !tierNorm.includes('NORMAL') && !tierNorm.includes('TIER_3')) {
          return false;
        }
      }

      if (searchPath.trim()) {
        const q = searchPath.toLowerCase();
        const matchesSpec = ep.spec_path?.toLowerCase().includes(q);
        const matchesSrc = ep.source_path?.toLowerCase().includes(q);
        const matchesMethod = ep.spec_method?.toLowerCase().includes(q) || ep.source_method?.toLowerCase().includes(q);
        if (!matchesSpec && !matchesSrc && !matchesMethod) return false;
      }

      return true;
    });
  }, [endpoints, tierFilter, searchPath]);

  // Aggregate stats
  const exactCount = endpoints.filter((e) => e.match_tier.toUpperCase().includes('EXACT') || e.match_tier.includes('1')).length;
  const paramCount = endpoints.filter((e) => e.match_tier.toUpperCase().includes('PARAM') || e.match_tier.includes('2')).length;
  const normCount = endpoints.filter((e) => e.match_tier.toUpperCase().includes('NORMAL') || e.match_tier.includes('3')).length;

  return (
    <div className="space-y-4">
      {/* Top Banner & Stats */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <GitCompare className="h-4 w-4 text-teal-400" />
              <span>Cross-Layer Endpoint Correlation Matrix</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic matching between OpenAPI contract declarations and source AST routing trees.
            </p>
          </div>
          <button
            onClick={fetchResults}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium rounded-md transition-colors shrink-0"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {/* Filter Controls Row */}
        <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 pt-2 border-t border-slate-800/80">
          <div className="sm:col-span-8 relative">
            <Search className="h-4 w-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchPath}
              onChange={(e) => setSearchPath(e.target.value)}
              placeholder="Search by endpoint path (/api/v1/users, {user_id})..."
              className="w-full bg-slate-950 border border-slate-800 focus:border-teal-500 focus:ring-1 focus:ring-teal-500 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 transition-colors font-mono"
            />
          </div>

          <div className="sm:col-span-4 flex items-center gap-2">
            <span className="text-slate-500 font-mono text-[11px] shrink-0">Tier:</span>
            <select
              value={tierFilter}
              onChange={(e) => setTierFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 text-xs font-mono focus:border-teal-500"
            >
              <option value="ALL">All Tiers ({endpoints.length})</option>
              <option value="EXACT">Tier 1: Exact Match ({exactCount})</option>
              <option value="PARAMETERIZED">Tier 2: Parameterized ({paramCount})</option>
              <option value="NORMALIZED">Tier 3: Normalized ({normCount})</option>
            </select>
          </div>
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="p-16 text-center flex flex-col items-center justify-center gap-3">
          <RefreshCw className="h-6 w-6 text-teal-400 animate-spin" />
          <p className="text-xs text-slate-400 font-mono">Loading correlation matrix for #{scanId.slice(0, 8)}...</p>
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div className="p-8 bg-slate-900 border border-slate-800 rounded-lg text-center flex flex-col items-center justify-center gap-3">
          <AlertCircle className="h-6 w-6 text-rose-400" />
          <p className="text-sm font-semibold text-slate-200">Unable to load correlation results</p>
          <p className="text-xs text-slate-400 max-w-md font-mono">{error}</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && filteredEndpoints.length === 0 && (
        <div className="p-12 bg-slate-900 border border-slate-800 rounded-lg text-center flex flex-col items-center justify-center gap-2">
          <Info className="h-8 w-8 text-slate-500" />
          <p className="text-sm font-semibold text-slate-200">No correlated endpoints found</p>
          <p className="text-xs text-slate-400">
            {endpoints.length === 0
              ? 'No endpoints could be correlated between the specification and source code.'
              : 'Try clearing your active path filter or tier selection.'}
          </p>
        </div>
      )}

      {/* Two-Pane Layout */}
      {!loading && !error && filteredEndpoints.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Left Table / List (7 cols) */}
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col max-h-[750px]">
            <div className="p-3 border-b border-slate-800 bg-slate-950/40 text-[11px] font-mono uppercase text-slate-400 flex justify-between">
              <span>Spec & Source Paths</span>
              <span>Match Tier</span>
            </div>
            <div className="overflow-y-auto divide-y divide-slate-800/60 flex-1">
              {filteredEndpoints.map((ep, idx) => {
                const isSelected = 
                  selectedEndpoint?.spec_path === ep.spec_path && 
                  selectedEndpoint?.spec_method === ep.spec_method;

                return (
                  <div
                    key={`${ep.spec_method}-${ep.spec_path}-${idx}`}
                    onClick={() => setSelectedEndpoint(ep)}
                    className={`p-3 cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-teal-500/10 border-l-2 border-teal-400'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1.5 min-w-0 flex-1">
                        {/* Spec line */}
                        <div className="flex items-center gap-2 font-mono text-xs truncate">
                          <span className="px-1.5 py-0.2 rounded bg-indigo-950/60 border border-indigo-700/60 text-indigo-300 font-bold text-[10px]">
                            {ep.spec_method}
                          </span>
                          <span className="text-slate-200 truncate" title={ep.spec_path}>
                            {ep.spec_path}
                          </span>
                        </div>

                        {/* Source line */}
                        <div className="flex items-center gap-2 font-mono text-[11px] truncate text-slate-400">
                          {ep.source_path ? (
                            <>
                              <span className="px-1.5 py-0.2 rounded bg-sky-950/60 border border-sky-700/60 text-sky-300 font-bold text-[10px]">
                                {ep.source_method || ep.spec_method}
                              </span>
                              <span className="text-slate-400 truncate" title={ep.source_path}>
                                {ep.source_path}
                              </span>
                            </>
                          ) : (
                            <span className="text-slate-500 italic text-[11px]">
                              [No matching source endpoint detected]
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="shrink-0 flex flex-col items-end gap-1">
                        <TierBadge tier={ep.match_tier} />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Detail Pane (5 cols) */}
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col space-y-5 max-h-[750px] overflow-y-auto">
            {selectedEndpoint ? (
              <>
                <div className="space-y-2 border-b border-slate-800 pb-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-mono uppercase text-slate-400">
                      Correlation Analysis
                    </span>
                    <TierBadge tier={selectedEndpoint.match_tier} />
                  </div>
                  <h3 className="text-sm font-semibold text-slate-100 font-mono">
                    {selectedEndpoint.spec_method} {selectedEndpoint.spec_path}
                  </h3>
                </div>

                {/* Specification Evidence Box */}
                <div className="space-y-2">
                  <h4 className="text-xs font-mono uppercase text-indigo-300 flex items-center gap-1.5">
                    <Layers className="h-3.5 w-3.5" />
                    <span>OpenAPI Contract Evidence</span>
                  </h4>
                  <div className="p-3 rounded bg-slate-950 border border-indigo-950 text-xs font-mono space-y-1.5">
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Declared Path</span>
                      <span className="text-slate-200">{selectedEndpoint.spec_path}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">HTTP Verb</span>
                      <span className="text-indigo-400 font-semibold">{selectedEndpoint.spec_method}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Status</span>
                      <span className="text-emerald-400">Present in OpenAPI Schema</span>
                    </div>
                  </div>
                </div>

                {/* Source Code Evidence Box */}
                <div className="space-y-2">
                  <h4 className="text-xs font-mono uppercase text-sky-300 flex items-center gap-1.5">
                    <FileCode className="h-3.5 w-3.5" />
                    <span>Source AST Route Evidence</span>
                  </h4>
                  <div className="p-3 rounded bg-slate-950 border border-sky-950 text-xs font-mono space-y-1.5">
                    {selectedEndpoint.source_path ? (
                      <>
                        <div>
                          <span className="text-slate-500 block text-[10px] uppercase">AST Route Pattern</span>
                          <span className="text-slate-200">{selectedEndpoint.source_path}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block text-[10px] uppercase">Handler Method</span>
                          <span className="text-sky-400 font-semibold">
                            {selectedEndpoint.source_method || selectedEndpoint.spec_method}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 block text-[10px] uppercase">Implementation State</span>
                          <span className="text-emerald-400">Verified via Source AST</span>
                        </div>
                      </>
                    ) : (
                      <div className="py-2 text-slate-400 text-xs italic">
                        Missing source implementation evidence. Endpoint exists in OpenAPI contract but was not resolved in application routing handlers.
                      </div>
                    )}
                  </div>
                </div>

                {/* Match Rationale & Algorithm */}
                <div className="space-y-2">
                  <h4 className="text-xs font-mono uppercase text-slate-400 flex items-center gap-1.5">
                    <Code2 className="h-3.5 w-3.5 text-teal-400" />
                    <span>Correlation Rationale</span>
                  </h4>
                  <div className="p-3 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 leading-relaxed">
                    {selectedEndpoint.rationale || 'Matched via normalized regex path pattern alignment.'}
                  </div>
                </div>

                {/* Epistemic distinction notice */}
                <div className="p-3 rounded bg-slate-950/40 border border-slate-800/60 text-[11px] text-slate-400 space-y-1">
                  <span className="font-semibold text-slate-300 block">Epistemic Rule:</span>
                  <p>
                    Missing source evidence signifies a contract-code divergence or shadow endpoint, but does not inherently constitute an exploitable vulnerability without independent security rule violations.
                  </p>
                </div>
              </>
            ) : (
              <div className="p-12 text-center text-slate-500 text-xs">
                Select an endpoint from the left to view dual-layer correlation evidence.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
