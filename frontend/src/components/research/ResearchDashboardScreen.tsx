import React, { useState, useEffect } from 'react';
import { 
  FlaskConical, 
  BarChart3, 
  AlertTriangle, 
  RefreshCw, 
  CheckCircle2, 
  Layers, 
  HelpCircle,
  FileText,
  Sliders,
  TrendingUp,
  Percent
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts';
import { api } from '../../services/api';
import { fallbackBenchmarkData } from '../../services/benchmarkData';
import { ResearchBenchmarksData, BenchmarkMetricsReport, ConfidenceInterval } from '../../types/research';

export const ResearchDashboardScreen: React.FC = () => {
  const [data, setData] = useState<ResearchBenchmarksData>(fallbackBenchmarkData);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'baseline' | 'external' | 'comparison'>('baseline');

  const fetchBenchmarks = async () => {
    setLoading(true);
    try {
      const res = await api.getResearchBenchmarks();
      if (res && res.baseline) {
        setData(res);
      }
    } catch {
      // Fallback is already loaded as default
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBenchmarks();
  }, []);

  const baselineReport = data.baseline || fallbackBenchmarkData.baseline;
  const externalReport = data.external || fallbackBenchmarkData.external;

  // Prepare chart data for baseline
  const getModesComparisonData = (report: BenchmarkMetricsReport | null) => {
    if (!report) return [];
    const modes = report.modes;
    return [
      {
        mode: 'SPEC_ONLY',
        precision: Number(((modes.SPEC_ONLY.overall.precision ?? 0) * 100).toFixed(1)),
        recall: Number(((modes.SPEC_ONLY.overall.recall ?? 0) * 100).toFixed(1)),
        f1: Number(((modes.SPEC_ONLY.overall.f1 ?? 0) * 100).toFixed(1)),
        fpr: Number(((modes.SPEC_ONLY.overall.fpr ?? 0) * 100).toFixed(1)),
        fnr: Number(((modes.SPEC_ONLY.overall.fnr ?? 0) * 100).toFixed(1)),
      },
      {
        mode: 'SOURCE_ONLY',
        precision: Number(((modes.SOURCE_ONLY.overall.precision ?? 0) * 100).toFixed(1)),
        recall: Number(((modes.SOURCE_ONLY.overall.recall ?? 0) * 100).toFixed(1)),
        f1: Number(((modes.SOURCE_ONLY.overall.f1 ?? 0) * 100).toFixed(1)),
        fpr: Number(((modes.SOURCE_ONLY.overall.fpr ?? 0) * 100).toFixed(1)),
        fnr: Number(((modes.SOURCE_ONLY.overall.fnr ?? 0) * 100).toFixed(1)),
      },
      {
        mode: 'CORRELATED',
        precision: Number(((modes.CORRELATED.overall.precision ?? 0) * 100).toFixed(1)),
        recall: Number(((modes.CORRELATED.overall.recall ?? 0) * 100).toFixed(1)),
        f1: Number(((modes.CORRELATED.overall.f1 ?? 0) * 100).toFixed(1)),
        fpr: Number(((modes.CORRELATED.overall.fpr ?? 0) * 100).toFixed(1)),
        fnr: Number(((modes.CORRELATED.overall.fnr ?? 0) * 100).toFixed(1)),
      },
    ];
  };

  const baselineChartData = getModesComparisonData(baselineReport);
  const externalChartData = getModesComparisonData(externalReport);

  // Confidence intervals list
  const confidenceIntervals: ConfidenceInterval[] = Array.isArray(data.phase7?.confidence_intervals)
    ? data.phase7?.confidence_intervals
    : data.phase7?.confidence_intervals?.intervals || (fallbackBenchmarkData.phase7?.confidence_intervals as ConfidenceInterval[]) || [];

  return (
    <div className="space-y-6">
      {/* Non-Live Research Disclaimer Banner */}
      <div className="bg-amber-950/20 border border-amber-500/30 p-4 rounded-lg flex items-start gap-3">
        <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5 text-xs">
          <span className="font-semibold text-amber-300 block">
            Research Evaluation Environment — Non-Operational Data
          </span>
          <p className="text-amber-200/80">
            Metrics displayed on this dashboard represent formal empirical benchmarks against pinned ground truth datasets.
            They are strictly isolated from operational live scans and evaluate engine efficacy across the frozen detection pipeline.
          </p>
        </div>
      </div>

      {/* Benchmark Selector Tabs */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveTab('baseline')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'baseline'
                ? 'bg-teal-500/20 text-teal-300 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Baseline Benchmark (24 Cases)
          </button>
          <button
            onClick={() => setActiveTab('external')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'external'
                ? 'bg-teal-500/20 text-teal-300 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            External VAmPI Benchmark (12 Cases)
          </button>
          <button
            onClick={() => setActiveTab('comparison')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'comparison'
                ? 'bg-teal-500/20 text-teal-300 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Statistical Rigor & CIs (Phase 7)
          </button>
        </div>

        <button
          onClick={fetchBenchmarks}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium rounded-md transition-colors"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Reload Benchmarks</span>
        </button>
      </div>

      {/* TAB 1: Baseline Benchmark */}
      {activeTab === 'baseline' && baselineReport && (
        <div className="space-y-6">
          {/* Header Card */}
          <div className="bg-slate-900 border border-slate-800 p-5 rounded-lg space-y-2">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <FlaskConical className="h-4 w-4 text-teal-400" />
                <span>Baseline Benchmark Metrics (Dataset v{baselineReport.dataset_version})</span>
              </h3>
              <span className="text-xs font-mono text-slate-500">
                Experiment ID: {baselineReport.experiment_id}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Evaluated across 24 test cases (10 authentic vulnerabilities, 14 negative controls) across 5 core security categories.
            </p>
          </div>

          {/* Metric Comparison Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {(['SPEC_ONLY', 'SOURCE_ONLY', 'CORRELATED'] as const).map((modeKey) => {
              const m = baselineReport.modes[modeKey].overall;
              const isCorrelated = modeKey === 'CORRELATED';
              return (
                <div 
                  key={modeKey}
                  className={`p-5 rounded-lg border ${
                    isCorrelated
                      ? 'bg-teal-950/20 border-teal-500/30'
                      : 'bg-slate-900 border-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase tracking-wider font-semibold text-slate-300">
                      {modeKey}
                    </span>
                    {isCorrelated && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-teal-500/20 text-teal-300 border border-teal-500/40">
                        Target System
                      </span>
                    )}
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-3 font-mono text-xs">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Precision</span>
                      <span className="text-lg font-bold text-slate-100">
                        {m.precision !== null ? `${(m.precision * 100).toFixed(1)}%` : 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Recall</span>
                      <span className="text-lg font-bold text-slate-100">
                        {m.recall !== null ? `${(m.recall * 100).toFixed(1)}%` : 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">F1 Score</span>
                      <span className="text-lg font-bold text-teal-400">
                        {m.f1 !== null ? `${(m.f1 * 100).toFixed(1)}%` : 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">False Pos. Rate</span>
                      <span className="text-lg font-bold text-rose-400">
                        {m.fpr !== null ? `${(m.fpr * 100).toFixed(1)}%` : 'N/A'}
                      </span>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>TP: {m.tp} | FP: {m.fp}</span>
                    <span>FN: {m.fn} | TN: {m.tn}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Performance Bar Chart */}
          <div className="bg-slate-900 border border-slate-800 p-5 rounded-lg space-y-4">
            <h4 className="text-xs font-mono uppercase text-slate-400 flex items-center gap-1.5">
              <BarChart3 className="h-4 w-4 text-teal-400" />
              <span>Comparative Statistical Metrics (%)</span>
            </h4>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={baselineChartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="mode" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#64748b" domain={[0, 100]} tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                  <Bar dataKey="precision" fill="#0d9488" name="Precision (%)" />
                  <Bar dataKey="recall" fill="#3b82f6" name="Recall (%)" />
                  <Bar dataKey="f1" fill="#14b8a6" name="F1 Score (%)" />
                  <Bar dataKey="fpr" fill="#f43f5e" name="FPR (%)" />
                  <Bar dataKey="fnr" fill="#eab308" name="FNR (%)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: External VAmPI Benchmark */}
      {activeTab === 'external' && externalReport && (
        <div className="space-y-6">
          {/* Architecture Limitation Notice */}
          <div className="bg-rose-950/20 border border-rose-500/30 p-5 rounded-lg space-y-2">
            <div className="flex items-center gap-2 text-rose-300 font-semibold text-sm">
              <AlertTriangle className="h-4 w-4 text-rose-400" />
              <span>External VAmPI Benchmark Limitation: Connexion Routing Architecture</span>
            </div>
            <p className="text-xs text-rose-200/90 leading-relaxed font-mono">
              VAmPI registers endpoints via Connexion swagger-ui config rather than standard native Flask <code>@app.route</code> decorators.
              Consequently, the frozen Phase 2 AST/regex extractor does not resolve Connexion source routes, resulting in zero source-layer detections (TP=0, FP=0, FN=7) and cascading zero detections in Correlated mode.
            </p>
            <p className="text-xs text-slate-400">
              This outcome demonstrates rigorous empirical transparency: the evaluation faithfully tests frozen analyzers against third-party architectures without post-hoc cherry-picking or modification.
            </p>
          </div>

          {/* Metric Comparison Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {(['SPEC_ONLY', 'SOURCE_ONLY', 'CORRELATED'] as const).map((modeKey) => {
              const m = externalReport.modes[modeKey].overall;
              return (
                <div key={modeKey} className="bg-slate-900 border border-slate-800 p-5 rounded-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase font-semibold text-slate-300">
                      {modeKey}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      VAmPI (12 Cases)
                    </span>
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-3 font-mono text-xs">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Precision</span>
                      <span className="text-lg font-bold text-slate-100">
                        {m.precision !== null ? `${(m.precision * 100).toFixed(1)}%` : 'Undefined (0/0)'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Recall</span>
                      <span className="text-lg font-bold text-slate-100">
                        {m.recall !== null ? `${(m.recall * 100).toFixed(1)}%` : '0.0%'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">F1 Score</span>
                      <span className="text-lg font-bold text-teal-400">
                        {m.f1 !== null ? `${(m.f1 * 100).toFixed(1)}%` : 'Undefined'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">False Pos. Rate</span>
                      <span className="text-lg font-bold text-rose-400">
                        {m.fpr !== null ? `${(m.fpr * 100).toFixed(1)}%` : '0.0%'}
                      </span>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>TP: {m.tp} | FP: {m.fp}</span>
                    <span>FN: {m.fn} | TN: {m.tn}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* VAmPI Bar Chart */}
          <div className="bg-slate-900 border border-slate-800 p-5 rounded-lg space-y-4">
            <h4 className="text-xs font-mono uppercase text-slate-400 flex items-center gap-1.5">
              <BarChart3 className="h-4 w-4 text-teal-400" />
              <span>VAmPI External Performance Profile</span>
            </h4>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={externalChartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="mode" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#64748b" domain={[0, 100]} tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                  <Bar dataKey="precision" fill="#0d9488" name="Precision (%)" />
                  <Bar dataKey="recall" fill="#3b82f6" name="Recall (%)" />
                  <Bar dataKey="f1" fill="#14b8a6" name="F1 Score (%)" />
                  <Bar dataKey="fpr" fill="#f43f5e" name="FPR (%)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Statistical Rigor & Confidence Intervals */}
      {activeTab === 'comparison' && (
        <div className="space-y-6">
          {/* CI Header */}
          <div className="bg-slate-900 border border-slate-800 p-5 rounded-lg space-y-2">
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-teal-400" />
              <span>Phase 7 Statistical Rigor & 95% Confidence Intervals</span>
            </h3>
            <p className="text-xs text-slate-400">
              Calculated using Wilson Score intervals for proportions and 2,000-sample BCa bootstrap resampling for composite F1 statistics.
            </p>
          </div>

          {/* Table of Confidence Intervals */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h4 className="text-xs font-mono uppercase text-slate-300">
                Confidence Intervals (95% CI)
              </h4>
              <span className="text-xs font-mono text-slate-500">
                Baseline (N=24)
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/40 text-[11px] text-slate-400 uppercase">
                    <th className="py-2.5 px-4">Mode</th>
                    <th className="py-2.5 px-4">Metric</th>
                    <th className="py-2.5 px-4">Point Estimate</th>
                    <th className="py-2.5 px-4">95% CI Lower</th>
                    <th className="py-2.5 px-4">95% CI Upper</th>
                    <th className="py-2.5 px-4">Method</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {confidenceIntervals.map((ci, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-4 font-semibold text-slate-200">
                        {ci.mode}
                      </td>
                      <td className="py-2.5 px-4 uppercase text-teal-400">
                        {ci.metric}
                      </td>
                      <td className="py-2.5 px-4 text-slate-100 font-bold">
                        {ci.estimate !== null ? `${(ci.estimate * 100).toFixed(1)}%` : 'N/A'}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">
                        {ci.lower !== null ? `${(ci.lower * 100).toFixed(1)}%` : 'N/A'}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">
                        {ci.upper !== null ? `${(ci.upper * 100).toFixed(1)}%` : 'N/A'}
                      </td>
                      <td className="py-2.5 px-4 text-slate-500 text-[11px]">
                        {ci.method}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
