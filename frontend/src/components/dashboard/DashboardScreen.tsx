import React, { useState, useEffect, useCallback } from 'react';
import { 
  PlusCircle, 
  RefreshCw, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  ArrowRight,
  AlertTriangle,
  FolderOpen,
  Layers,
  Activity
} from 'lucide-react';
import { api } from '../../services/api';
import { ScanResponse } from '../../types/scan';
import { Badge, StatusBadge, SeverityBadge } from '../common/Badge';

interface DashboardScreenProps {
  onNavigate: (screen: any, scanId?: string) => void;
  onSelectScan: (scanId: string) => void;
}

export const DashboardScreen: React.FC<DashboardScreenProps> = ({
  onNavigate,
  onSelectScan
}) => {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listScans(20);
      setScans(data);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch scan activity.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Aggregate stats
  const totalScans = scans.length;
  const completedScans = scans.filter((s) => s.status?.toUpperCase() === 'COMPLETED').length;
  const failedScans = scans.filter((s) => s.status?.toUpperCase() === 'FAILED').length;
  const activeScans = scans.filter((s) => ['QUEUED', 'RUNNING'].includes(s.status?.toUpperCase())).length;

  return (
    <div className="space-y-6">
      {/* Top Banner / Quick Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-5 rounded-lg">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Security Analysis Activity</h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time status of dual-layer OpenAPI specification and source code security audits.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchScans()}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium rounded-md transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => onNavigate('new-scan')}
            className="flex items-center gap-2 px-4 py-2 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold rounded-md shadow-xs transition-colors"
          >
            <PlusCircle className="h-4 w-4" />
            <span>New Scan</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Runs */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">Total Scans</span>
            <FolderOpen className="h-4 w-4 text-slate-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-100">{totalScans}</span>
            <span className="text-[11px] text-slate-500">recorded</span>
          </div>
        </div>

        {/* Completed */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">Completed</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-400">{completedScans}</span>
            <span className="text-[11px] text-slate-500">
              {totalScans > 0 ? `${Math.round((completedScans / totalScans) * 100)}%` : '0%'}
            </span>
          </div>
        </div>

        {/* Failed */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">Failed / Aborted</span>
            <XCircle className="h-4 w-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-rose-400">{failedScans}</span>
            <span className="text-[11px] text-slate-500">unsuccessful</span>
          </div>
        </div>

        {/* In Progress */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">Active Pipeline</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-cyan-400">{activeScans}</span>
            <span className="text-[11px] text-slate-500">queued/running</span>
          </div>
        </div>
      </div>

      {/* Main Table: Recent Scans */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-slate-400" />
            <h3 className="text-sm font-semibold text-slate-100">Recent Security Audits</h3>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            Showing latest {scans.length}
          </span>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="p-12 text-center flex flex-col items-center justify-center gap-3">
            <RefreshCw className="h-6 w-6 text-teal-400 animate-spin" />
            <p className="text-xs text-slate-400 font-mono">Loading scan records from database...</p>
          </div>
        )}

        {/* Error State */}
        {!loading && error && (
          <div className="p-8 text-center flex flex-col items-center justify-center gap-3">
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-full text-rose-400">
              <AlertTriangle className="h-6 w-6" />
            </div>
            <p className="text-sm font-medium text-slate-200">Unable to load scans</p>
            <p className="text-xs text-slate-400 max-w-md font-mono">{error}</p>
            <button
              onClick={() => fetchScans()}
              className="mt-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 rounded border border-slate-700"
            >
              Retry
            </button>
          </div>
        )}

        {/* Empty State */}
        {!loading && !error && scans.length === 0 && (
          <div className="p-12 text-center flex flex-col items-center justify-center gap-3">
            <div className="p-3 bg-slate-800 rounded-full text-slate-500">
              <FolderOpen className="h-6 w-6" />
            </div>
            <p className="text-sm font-medium text-slate-200">No scans found</p>
            <p className="text-xs text-slate-400 max-w-sm">
              No API security scans have been initiated yet. Upload an OpenAPI spec and source archive to run your first correlation audit.
            </p>
            <button
              onClick={() => onNavigate('new-scan')}
              className="mt-2 px-4 py-2 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold rounded-md shadow-xs"
            >
              Create New Scan
            </button>
          </div>
        )}

        {/* Data Table */}
        {!loading && !error && scans.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/40 text-[11px] font-mono uppercase text-slate-400">
                  <th className="py-3 px-4">Project</th>
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created At</th>
                  <th className="py-3 px-4">Completed At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {scans.map((scan) => {
                  const sId = scan.scan_id || scan.id || '';
                  return (
                    <tr 
                      key={sId}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                      onClick={() => {
                        onSelectScan(sId);
                        onNavigate('scan-details', sId);
                      }}
                    >
                      <td className="py-3 px-4 text-slate-200 font-sans font-medium">
                        {scan.project_name || 'Unnamed Project'}
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono">
                        <span className="text-teal-400 group-hover:underline">
                          {sId.slice(0, 8)}
                        </span>
                        <span className="text-slate-600">...{sId.slice(-4)}</span>
                      </td>
                      <td className="py-3 px-4 font-sans">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'}
                      </td>
                      <td className="py-3 px-4 text-right font-sans">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectScan(sId);
                              onNavigate('scan-details', sId);
                            }}
                            className="p-1.5 text-slate-400 hover:text-teal-300 rounded hover:bg-slate-800 transition-colors"
                            title="View scan details"
                          >
                            <ArrowRight className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Benchmark Reference Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-teal-500/10 border border-teal-500/30 text-teal-400 font-medium">
              Research & Evaluation
            </span>
            <span className="text-xs text-slate-400">Phase 7.3 Multi-Benchmark Validation</span>
          </div>
          <p className="text-xs text-slate-300">
            Compare statistical precision, recall, FPR and FNR across 24 baseline benchmark cases and 12 external VAmPI benchmark cases.
          </p>
        </div>
        <button
          onClick={() => onNavigate('research')}
          className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-teal-300 text-xs font-medium rounded-md transition-colors shrink-0"
        >
          <span>Open Research Benchmark</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
};
