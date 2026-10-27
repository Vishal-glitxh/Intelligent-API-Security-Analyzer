import React, { useState, useEffect } from 'react';
import { 
  FlaskConical, 
  BarChart3, 
  AlertTriangle, 
  RefreshCw, 
  TrendingUp,
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
} from 'recharts';
import { api } from '../../services/api';
import { ResearchBenchmarksData, BenchmarkMetricsReport, ConfidenceInterval, ModeComparison } from '../../types/research';
import { formatResearchPercent, toResearchChartPercent } from '../../utils/research';

export const ResearchDashboardScreen: React.FC = () => {
  const [data, setData] = useState<ResearchBenchmarksData | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'baseline' | 'external' | 'comparison'>('baseline');

  useEffect(() => {
    let active = true;
    void api.getResearchBenchmarks()
      .then((res) => {
        if (active && (res?.baseline || res?.external)) setData(res);
        else if (active) setLoadError('The benchmark service returned no published evaluation data.');
      })
      .catch((error: unknown) => {
        if (active) setLoadError(error instanceof Error ? error.message : 'Research benchmarks could not be loaded.');
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const reloadBenchmarks = async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await api.getResearchBenchmarks();
      if (!res?.baseline && !res?.external) throw new Error('The benchmark service returned no published evaluation data.');
      setData(res);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : 'Research benchmarks could not be refreshed.');
    } finally {
      setLoading(false);
    }
  };

  const baselineReport = data?.baseline ?? null;
  const externalReport = data?.external ?? null;

  // Prepare chart data for baseline
  const getModesComparisonData = (report: BenchmarkMetricsReport | null) => {
    if (!report) return [];
    const modes = report.modes;
    return (['SPEC_ONLY', 'SOURCE_ONLY', 'CORRELATED'] as const).map((mode) => {
      const metrics = modes[mode].overall;
      return {
        mode,
        precision: toResearchChartPercent(metrics.precision),
        recall: toResearchChartPercent(metrics.recall),
        f1: toResearchChartPercent(metrics.f1),
        fpr: toResearchChartPercent(metrics.fpr),
        fnr: toResearchChartPercent(metrics.fnr),
      };
    });
  };

  const baselineChartData = getModesComparisonData(baselineReport);
  const externalChartData = getModesComparisonData(externalReport);

  // Confidence intervals list
  const intervals = data?.phase7?.confidence_intervals;
  const confidenceIntervals: ConfidenceInterval[] = Array.isArray(intervals)
    ? intervals
    : intervals?.intervals || [];
  const rawComparisons = data?.phase7?.mode_comparisons;
  const modeComparisons: ModeComparison[] = Array.isArray(rawComparisons)
    ? rawComparisons
    : rawComparisons?.comparisons || [];

  const pageIntro = (
    <section className="page-intro">
      <div>
        <div className="page-eyebrow"><span className="page-eyebrow-mark" /> Evidence & repeatability</div>
        <h2 className="page-heading">Research benchmarks</h2>
        <p className="page-description">Compare published baseline and external evaluations. These research metrics are separate from live scan activity.</p>
      </div>
    </section>
  );

  if (loading && !data) {
    return <>{pageIntro}<div className="screen-loader" role="status"><RefreshCw className="h-5 w-5 animate-spin" /> Loading published research data</div></>;
  }

  if (!data || (!baselineReport && !externalReport)) {
    return <>{pageIntro}<div className="surface-card empty-state" role="alert"><span className="empty-state-icon"><AlertTriangle /></span><h3>Published benchmarks unavailable</h3><p>{loadError || 'The API has no published benchmark artifacts configured.'}</p><button className="button button-primary" onClick={reloadBenchmarks} disabled={loading}><RefreshCw className={loading ? 'animate-spin' : ''} /> Retry</button></div></>;
  }

  return (
    <div className="space-y-6">
      {pageIntro}
      {loadError && <div className="surface-card p-4 text-xs text-amber-800" role="status">Refresh failed. Showing the last benchmark response from the API: {loadError}</div>}
      {/* Non-Live Research Disclaimer Banner */}
      <div className="bg-amber-950/20 border border-amber-500/30 p-4 rounded-lg flex items-start gap-3">
        <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5 text-xs">
          <span className="font-semibold text-amber-300 block">
            Research Evaluation Environment — Non-Operational Data
          </span>
          <p className="text-amber-200/80">
            Metrics displayed on this dashboard represent formal empirical benchmarks against pinned ground truth datasets.
            These values come from published evaluation artifacts and are isolated from live scans. They describe the analyzer version recorded in each run, not necessarily the current working-tree implementation.
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
          onClick={reloadBenchmarks}
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
                        {formatResearchPercent(m.precision)}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Recall</span>
                      <span className="text-lg font-bold text-slate-100">
                        {formatResearchPercent(m.recall)}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">F1 Score</span>
                      <span className="text-lg font-bold text-teal-400">
                        {formatResearchPercent(m.f1)}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">False Pos. Rate</span>
                      <span className="text-lg font-bold text-rose-400">
                        {formatResearchPercent(m.fpr)}
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
                  <CartesianGrid strokeDasharray="3 3" stroke="#e7ebf2" />
                  <XAxis dataKey="mode" stroke="#8794a7" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#8794a7" domain={[0, 100]} tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e4e9f1', borderRadius: '12px', color: '#24344c', fontSize: '11px', boxShadow: '0 10px 30px rgba(27, 45, 75, .12)' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                  <Bar dataKey="precision" fill="#315efb" name="Precision (%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="recall" fill="#57a1e8" name="Recall (%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="f1" fill="#18a873" name="F1 Score (%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="fpr" fill="#e04462" name="FPR (%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="fnr" fill="#c27b0a" name="FNR (%)" radius={[4, 4, 0, 0]} />
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
              <span>Published VAmPI Run: Connexion Route Coverage</span>
            </div>
            <p className="text-xs text-rose-200/90 leading-relaxed font-mono">
              VAmPI registers endpoints through Connexion OpenAPI operation IDs rather than Flask route decorators. This published report predates the current workspace's static operation-ID mapping, so its zero source-layer detections (TP=0, FP=0, FN=7) and correlated results describe the earlier analyzer version.
            </p>
            <p className="text-xs text-slate-400">
              The published result remains unchanged for reproducibility. A fresh evaluation is required before making claims about the current analyzer's Connexion coverage.
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
                        {formatResearchPercent(m.precision)}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Recall</span>
                      <span className="text-lg font-bold text-slate-100">
                        {formatResearchPercent(m.recall)}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">F1 Score</span>
                      <span className="text-lg font-bold text-teal-400">
                        {formatResearchPercent(m.f1)}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">False Pos. Rate</span>
                      <span className="text-lg font-bold text-rose-400">
                        {formatResearchPercent(m.fpr)}
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
                  <CartesianGrid strokeDasharray="3 3" stroke="#e7ebf2" />
                  <XAxis dataKey="mode" stroke="#8794a7" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#8794a7" domain={[0, 100]} tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e4e9f1', borderRadius: '12px', color: '#24344c', fontSize: '11px', boxShadow: '0 10px 30px rgba(27, 45, 75, .12)' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                  <Bar dataKey="precision" fill="#315efb" name="Precision (%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="recall" fill="#57a1e8" name="Recall (%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="f1" fill="#18a873" name="F1 Score (%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="fpr" fill="#e04462" name="FPR (%)" radius={[4, 4, 0, 0]} />
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
              Wilson score intervals are used for proportions and 10,000-resample percentile bootstrap intervals for F1. Sample sizes vary by metric; intervals are descriptive and do not imply statistical significance.
            </p>
          </div>

          {/* Table of Confidence Intervals */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h4 className="text-xs font-mono uppercase text-slate-300">
                Confidence Intervals (95% CI)
              </h4>
              <span className="text-xs font-mono text-slate-500">
                Baseline evaluation; sample size varies by metric
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
                    <th className="py-2.5 px-4">N</th>
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
                        {formatResearchPercent(ci.estimate)}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">
                        {formatResearchPercent(ci.lower)}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">
                        {formatResearchPercent(ci.upper)}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">{ci.sample_size ?? '—'}</td>
                      <td className="py-2.5 px-4 text-slate-500 text-[11px]">
                        {ci.method.replaceAll('_', ' ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="surface-card overflow-hidden">
            <div className="surface-header">
              <h4 className="surface-title">Mode comparisons</h4>
              <span className="surface-meta">Published statistical report</span>
            </div>
            {modeComparisons.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="activity-table">
                  <thead><tr><th>Metric</th><th>Comparison</th><th>Difference</th><th>Significance</th><th>Interpretation</th></tr></thead>
                  <tbody>{modeComparisons.map((comparison, index) => {
                    const delta = comparison.absolute_difference ?? comparison.difference;
                    const isSignificant = comparison.statistically_significant ?? comparison.significant;
                    const label = comparison.comparison || `${comparison.comparison_mode ?? '—'} vs ${comparison.baseline_mode ?? '—'}`;
                    return (
                      <tr key={`${comparison.metric}-${label}-${index}`}>
                        <td>{comparison.metric.toUpperCase()}</td>
                        <td>{label}</td>
                        <td>{delta === undefined ? 'N/A' : formatResearchPercent(delta)}</td>
                        <td>{isSignificant === undefined ? 'Not reported' : isSignificant ? 'Significant' : 'Not significant'}</td>
                        <td>{comparison.notes || 'No interpretation supplied in the published report.'}</td>
                      </tr>
                    );
                  })}</tbody>
                </table>
              </div>
            ) : <div className="empty-state"><p>No mode-comparison artifact is available from the research API.</p></div>}
          </div>
        </div>
      )}
    </div>
  );
};
