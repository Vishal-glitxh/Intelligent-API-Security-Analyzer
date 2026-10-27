import React, { useEffect, useState } from 'react';
import {
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  FileSearch,
  Layers3,
  Plus,
  RefreshCw,
  ShieldAlert,
  XCircle,
} from 'lucide-react';
import { api } from '../../services/api';
import { ScanResponse } from '../../types/scan';
import { StatusBadge } from '../common/Badge';
import { ScreenId } from '../common/Sidebar';

interface DashboardScreenProps {
  onNavigate: (screen: ScreenId, scanId?: string) => void;
  onSelectScan: (scanId: string) => void;
}

const formatDate = (value: string) => new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit',
}).format(new Date(value));

export const DashboardScreen: React.FC<DashboardScreenProps> = ({ onNavigate, onSelectScan }) => {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void api.listScans(20)
      .then((data) => { if (active) setScans(data); })
      .catch((cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : 'Unable to load scan activity.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      setScans(await api.listScans(20));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load scan activity.');
    } finally {
      setLoading(false);
    }
  };

  const completed = scans.filter((scan) => scan.status?.toUpperCase() === 'COMPLETED').length;
  const failed = scans.filter((scan) => scan.status?.toUpperCase() === 'FAILED').length;
  const active = scans.filter((scan) => ['QUEUED', 'RUNNING'].includes(scan.status?.toUpperCase())).length;
  const openScan = (scanId: string) => {
    onSelectScan(scanId);
    onNavigate('scan-details', scanId);
  };

  return (
    <div className="dashboard-page">
      <section className="page-intro">
        <div>
          <div className="page-eyebrow"><span className="page-eyebrow-mark" /> Security operations <span aria-hidden="true">·</span> analyst workspace</div>
          <h2 className="page-heading">Your security overview</h2>
          <p className="page-description">One place to track API assessments, investigate findings, and understand how your contracts compare with implementation.</p>
        </div>
        <div className="dashboard-actions">
          <button type="button" onClick={() => void refresh()} disabled={loading} className="button button-secondary">
            <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          <button type="button" onClick={() => onNavigate('new-scan')} className="button button-primary">
            <Plus size={16} /> New assessment
          </button>
        </div>
      </section>

      <section className="metric-grid" aria-label="Assessment summary">
        <article className="metric-card">
          <div className="metric-top"><span>Total assessments</span><span className="metric-icon blue"><Layers3 /></span></div>
          <div className="metric-value">{scans.length}</div>
          <div className="metric-foot">Latest 20 scan records</div>
        </article>
        <article className="metric-card">
          <div className="metric-top"><span>Completed</span><span className="metric-icon green"><CheckCircle2 /></span></div>
          <div className="metric-value">{completed}</div>
          <div className="metric-foot">{scans.length ? `${Math.round((completed / scans.length) * 100)}% of recent activity` : 'Ready for your first assessment'}</div>
        </article>
        <article className="metric-card">
          <div className="metric-top"><span>Requires attention</span><span className="metric-icon red"><XCircle /></span></div>
          <div className="metric-value">{failed}</div>
          <div className="metric-foot">Failed or interrupted scans</div>
        </article>
        <article className="metric-card">
          <div className="metric-top"><span>In progress</span><span className="metric-icon cyan"><Clock3 /></span></div>
          <div className="metric-value">{active}</div>
          <div className="metric-foot">Queued or currently running</div>
        </article>
      </section>

      <section className="workspace-grid">
        <div className="surface-card activity-panel">
          <div className="surface-header">
            <div>
              <div className="surface-title"><FileSearch /> Recent assessments</div>
              <div className="surface-meta mt-1">Your latest API security analysis runs</div>
            </div>
            <span className="surface-meta">{scans.length} records</span>
          </div>

          {loading && scans.length === 0 && (
            <div className="empty-state" role="status"><RefreshCw className="animate-spin text-blue-500" size={22} /><p>Loading your assessments…</p></div>
          )}

          {!loading && error && (
            <div className="empty-state">
              <span className="empty-state-icon"><ShieldAlert size={21} /></span>
              <h3>Couldn’t load assessments</h3>
              <p>{error}</p>
              <button type="button" onClick={() => void refresh()} className="button button-secondary">Try again</button>
            </div>
          )}

          {!loading && !error && scans.length === 0 && (
            <div className="empty-state">
              <span className="empty-state-icon"><Layers3 size={21} /></span>
              <h3>Your workspace is ready</h3>
              <p>Start with an OpenAPI document and source archive to create your first evidence-led assessment.</p>
              <button type="button" onClick={() => onNavigate('new-scan')} className="button button-primary"><Plus size={15} /> Start an assessment</button>
            </div>
          )}

          {!error && scans.length > 0 && (
            <div className="overflow-x-auto">
              <table className="activity-table">
                <thead>
                  <tr><th>Project</th><th>Scan ID</th><th>Status</th><th>Created</th><th><span className="sr-only">Open scan</span></th></tr>
                </thead>
                <tbody>
                  {scans.map((scan) => {
                    const id = scan.scan_id || scan.id || '';
                    return (
                      <tr key={id} className="activity-row">
                        <td className="project-cell">{scan.project_name || 'Unnamed project'}</td>
                        <td><span className="scan-id" title={id}>{id.slice(0, 8)}…</span></td>
                        <td><StatusBadge status={scan.status} /></td>
                        <td>{formatDate(scan.created_at)}</td>
                        <td className="text-right">
                          <button type="button" className="row-open-button" onClick={() => openScan(id)} aria-label={`Open ${scan.project_name || 'scan'} details`} title="Open scan">
                            <ArrowUpRight size={16} />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <aside className="research-callout">
          <div className="research-kicker">Independent evaluation</div>
          <h3>Built on reproducible evidence.</h3>
          <p>Explore how specification analysis, static source inspection, and deterministic correlation perform across frozen benchmark sets.</p>
          <div className="research-stats">
            <div className="research-stat"><strong>24</strong><span>baseline cases</span></div>
            <div className="research-stat"><strong>12</strong><span>external cases</span></div>
          </div>
          <button type="button" className="research-link" onClick={() => onNavigate('research')}>
            Explore benchmark results <ArrowRight size={14} />
          </button>
        </aside>
      </section>
    </div>
  );
};
