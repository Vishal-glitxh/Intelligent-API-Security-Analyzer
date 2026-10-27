import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  RefreshCw, 
  Clock, 
  CheckCircle2, 
  AlertTriangle, 
  FileText, 
  ShieldAlert, 
  GitCompare, 
  ArrowRight,
  Calendar,
  KeyRound,
} from 'lucide-react';
import { api } from '../../services/api';
import { ScanResponse, ScanResultsResponse } from '../../types/scan';
import { StatusBadge } from '../common/Badge';

interface ScanDetailsScreenProps {
  scanId: string;
  onNavigate: (screen: any, scanId?: string) => void;
}

export const ScanDetailsScreen: React.FC<ScanDetailsScreenProps> = ({
  scanId,
  onNavigate
}) => {
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [results, setResults] = useState<ScanResultsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pollCount, setPollCount] = useState(0);

  const isMountedRef = useRef(true);

  const fetchScanData = useCallback(async () => {
    try {
      const scanData = await api.getScan(scanId);
      if (!isMountedRef.current) return;
      setScan(scanData);
      setError(null);

      if (scanData.status === 'COMPLETED') {
        try {
          const resultsData = await api.getScanResults(scanId);
          if (isMountedRef.current) {
            setResults(resultsData);
          }
        } catch {
          // Results endpoint optional or empty
        }
      }
    } catch (err: any) {
      if (isMountedRef.current) {
        setError(err.message || 'Failed to fetch scan details.');
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [scanId]);

  // Initial fetch and polling logic with cleanup
  useEffect(() => {
    isMountedRef.current = true;
    // eslint-disable-next-line react/set-state-in-effect -- This starts the initial API request; its state updates run after it settles.
    fetchScanData();

    // Poll while QUEUED or RUNNING
    const interval = setInterval(() => {
      const statusUpper = scan?.status?.toUpperCase();
      if (statusUpper === 'QUEUED' || statusUpper === 'RUNNING') {
        setPollCount((prev) => prev + 1);
        fetchScanData();
      }
    }, 3000);

    return () => {
      isMountedRef.current = false;
      clearInterval(interval);
    };
  }, [scanId, scan?.status, fetchScanData]);

  if (loading && !scan) {
    return (
      <div className="p-16 text-center flex flex-col items-center justify-center gap-3">
        <RefreshCw className="h-6 w-6 text-teal-400 animate-spin" />
        <p className="text-xs text-slate-400 font-mono">Loading scan status for #{scanId.slice(0, 8)}...</p>
      </div>
    );
  }

  if (error && !scan) {
    return (
      <div className="p-8 bg-slate-900 border border-slate-800 rounded-lg text-center flex flex-col items-center justify-center gap-3">
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-full text-rose-400">
          <AlertTriangle className="h-6 w-6" />
        </div>
        <p className="text-sm font-semibold text-slate-200">Unable to load scan</p>
        <p className="text-xs text-slate-400 max-w-md font-mono">{error}</p>
        <button
          onClick={() => {
            setLoading(true);
            fetchScanData();
          }}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 rounded border border-slate-700"
        >
          Retry
        </button>
      </div>
    );
  }

  const statusUpper = scan?.status?.toUpperCase();
  const isCompleted = statusUpper === 'COMPLETED';
  const isFailed = statusUpper === 'FAILED';
  const isRunning = statusUpper === 'QUEUED' || statusUpper === 'RUNNING';
  const effectiveId = scan?.scan_id || scan?.id || scanId;

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1 min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-slate-100 truncate">
              {scan?.project_name || 'Unnamed Project Scan'}
            </h2>
            {scan && <StatusBadge status={scan.status} />}
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
            <span>Scan ID:</span>
            <span className="text-slate-300 select-all">{effectiveId}</span>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={() => fetchScanData()}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium rounded-md transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRunning ? 'animate-spin text-teal-400' : ''}`} />
            <span>{isRunning ? 'Polling status...' : 'Refresh'}</span>
          </button>
          {isCompleted && (
            <button
              onClick={() => onNavigate('findings', scanId)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold rounded-md shadow-xs transition-colors"
            >
              <span>Explore Findings</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Failure Alert Box */}
      {isFailed && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-lg flex items-start gap-3 text-xs text-rose-300">
          <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold block text-sm">Scan Execution Failed</span>
            <p className="text-rose-200/90 font-mono">
              {scan?.error_message || 'An error occurred during analysis execution.'}
            </p>
            <p className="text-[11px] text-slate-400 pt-1">
              Internal stack traces and secrets are filtered to preserve security boundaries. Review OpenAPI format validity and source archive structure.
            </p>
          </div>
        </div>
      )}

      {/* Polling In-Progress Banner */}
      {isRunning && (
        <div className="p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-between gap-3 text-xs text-cyan-300">
          <div className="flex items-center gap-3">
            <RefreshCw className="h-4 w-4 animate-spin text-cyan-400 shrink-0" />
            <div>
              <span className="font-semibold block">Analysis in progress...</span>
              <span className="text-slate-400 text-[11px]">
                The background engine is parsing OpenAPI contracts, generating ASTs, and resolving cross-layer correlations.
              </span>
            </div>
          </div>
          <span className="text-[11px] font-mono text-slate-400 shrink-0">
            Auto-polling every 3s (ticks: {pollCount})
          </span>
        </div>
      )}

      {/* Metadata Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Creation Timestamp */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
            <span>Created At</span>
            <Calendar className="h-4 w-4 text-slate-500" />
          </div>
          <div className="mt-2 text-xs font-mono text-slate-200">
            {scan?.created_at ? new Date(scan.created_at).toLocaleString() : '—'}
          </div>
        </div>

        {/* Completion Timestamp */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
            <span>Completed At</span>
            <Clock className="h-4 w-4 text-slate-500" />
          </div>
          <div className="mt-2 text-xs font-mono text-slate-200">
            {scan?.completed_at ? new Date(scan.completed_at).toLocaleString() : 'In progress / Pending'}
          </div>
        </div>

        {/* Execution Time */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
            <span>Execution Duration</span>
            <Clock className="h-4 w-4 text-teal-400" />
          </div>
          <div className="mt-2 text-base font-semibold font-mono text-slate-200">
            {scan?.metrics?.execution_time_ms ? `${scan.metrics.execution_time_ms} ms` : '—'}
          </div>
        </div>

        {/* Client ID / Owner */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
            <span>Owner / Client</span>
            <KeyRound className="h-4 w-4 text-slate-500" />
          </div>
          <div className="mt-2 text-xs font-mono text-slate-300 truncate" title={scan?.client_id || 'System'}>
            {scan?.client_id || 'analyst-client'}
          </div>
        </div>
      </div>

      {/* Completed Results Summary */}
      {isCompleted && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-slate-100">Analysis Summary & Metrics</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Deterministic Dual-Layer Results
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-1">
            <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">Spec Endpoints</span>
              <span className="text-xl font-bold text-slate-100">
                {results?.metrics_summary?.total_spec_endpoints ?? (scan?.metrics?.spec_endpoints_count ?? '—')}
              </span>
            </div>
            <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">Source Endpoints</span>
              <span className="text-xl font-bold text-slate-100">
                {results?.metrics_summary?.total_source_endpoints ?? (scan?.metrics?.source_endpoints_count ?? '—')}
              </span>
            </div>
            <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">Correlated Endpoints</span>
              <span className="text-xl font-bold text-teal-400">
                {results?.metrics_summary?.matched_endpoints_count ?? (scan?.metrics?.matched_endpoints_count ?? '—')}
              </span>
            </div>
            <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">Total Vulnerabilities</span>
              <span className="text-xl font-bold text-rose-400">
                {results?.metrics_summary
                  ? (Number(results.metrics_summary.spec_only_findings_count ?? 0) +
                     Number(results.metrics_summary.source_only_findings_count ?? 0) +
                     Number(results.metrics_summary.correlated_findings_count ?? 0))
                  : (scan?.metrics?.total_findings ?? '—')}
              </span>
            </div>
          </div>

          {/* Quick Screen Navigation Links */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
            <button
              onClick={() => onNavigate('findings', scanId)}
              className="p-3 rounded bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 flex items-center justify-between text-left transition-colors group"
            >
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="h-4 w-4 text-rose-400" />
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-teal-300">
                    Findings Explorer
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Filter by severity and layer
                  </div>
                </div>
              </div>
              <ArrowRight className="h-3.5 w-3.5 text-slate-500 group-hover:text-teal-400" />
            </button>

            <button
              onClick={() => onNavigate('correlation', scanId)}
              className="p-3 rounded bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 flex items-center justify-between text-left transition-colors group"
            >
              <div className="flex items-center gap-2.5">
                <GitCompare className="h-4 w-4 text-cyan-400" />
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-teal-300">
                    Endpoint Correlation
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Trace match tiers and rationale
                  </div>
                </div>
              </div>
              <ArrowRight className="h-3.5 w-3.5 text-slate-500 group-hover:text-teal-400" />
            </button>

            <button
              onClick={() => onNavigate('reports', scanId)}
              className="p-3 rounded bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 flex items-center justify-between text-left transition-colors group"
            >
              <div className="flex items-center gap-2.5">
                <FileText className="h-4 w-4 text-emerald-400" />
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-teal-300">
                    Reports & Export
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Download JSON and HTML reports
                  </div>
                </div>
              </div>
              <ArrowRight className="h-3.5 w-3.5 text-slate-500 group-hover:text-teal-400" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
