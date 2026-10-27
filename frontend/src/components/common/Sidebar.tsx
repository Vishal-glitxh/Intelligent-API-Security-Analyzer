import React from 'react';
import {
  Activity,
  BarChart3,
  FileSearch,
  FileText,
  GitCompare,
  LayoutDashboard,
  Plus,
  ShieldCheck,
} from 'lucide-react';

export type ScreenId =
  | 'dashboard'
  | 'new-scan'
  | 'scan-details'
  | 'findings'
  | 'correlation'
  | 'research'
  | 'reports';

interface SidebarProps {
  currentScreen: ScreenId;
  onNavigate: (screen: ScreenId, scanId?: string) => void;
  selectedScanId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentScreen,
  onNavigate,
  selectedScanId,
  isOpen,
  onClose,
}) => {
  const workspaceItems = [
    { id: 'dashboard' as const, label: 'Overview', icon: LayoutDashboard },
    { id: 'new-scan' as const, label: 'New assessment', icon: Plus },
    { id: 'research' as const, label: 'Research benchmarks', icon: BarChart3 },
  ];
  const analysisItems = [
    { id: 'scan-details' as const, label: 'Scan summary', icon: FileSearch },
    { id: 'findings' as const, label: 'Findings explorer', icon: Activity },
    { id: 'correlation' as const, label: 'Endpoint correlation', icon: GitCompare },
    { id: 'reports' as const, label: 'Reports & exports', icon: FileText },
  ];

  const renderItem = (item: (typeof workspaceItems)[number] | (typeof analysisItems)[number], scoped = false) => {
    const Icon = item.icon;
    const disabled = scoped && !selectedScanId;
    const active = currentScreen === item.id;
    return (
      <button
        key={item.id}
        type="button"
        className={`nav-item${active ? ' is-active' : ''}`}
        disabled={disabled}
        aria-current={active ? 'page' : undefined}
        onClick={() => {
          if (disabled) return;
          onNavigate(item.id, scoped ? selectedScanId ?? undefined : undefined);
          onClose();
        }}
        title={disabled ? 'Select a scan to open this view' : item.label}
      >
        <Icon aria-hidden="true" />
        <span className="nav-item-label">{item.label}</span>
      </button>
    );
  };

  return (
    <>
      {isOpen && <button className="app-backdrop" onClick={onClose} aria-label="Close navigation" />}
      <aside className={`app-sidebar${isOpen ? ' is-open' : ''}`} aria-label="Main navigation">
        <div className="brand-lockup">
          <span className="brand-symbol"><ShieldCheck size={22} strokeWidth={2.2} /></span>
          <span>
            <span className="brand-title block">API Security Analyzer</span>
            <span className="brand-caption block">Research workspace</span>
          </span>
        </div>
        <div className="sidebar-rule" />

        <nav className="flex-1 overflow-y-auto" aria-label="Workspace sections">
          <section className="nav-group">
            <h2 className="nav-label">Workspace</h2>
            <div className="nav-list">{workspaceItems.map((item) => renderItem(item))}</div>
          </section>

          <section className="nav-group">
            <h2 className="nav-label flex items-center justify-between">
              <span>Selected scan</span>
              <span className="sidebar-context" title={selectedScanId ?? undefined}>
                {selectedScanId ? `#${selectedScanId.slice(0, 8)}` : 'None'}
              </span>
            </h2>
            <div className="nav-list">{analysisItems.map((item) => renderItem(item, true))}</div>
          </section>
        </nav>

        <div className="sidebar-bottom">
          <div className="corpus-card">
            <div className="corpus-topline"><span>Evidence-led analysis</span><span className="corpus-dot" /></div>
            <p>OpenAPI rules, static source analysis, and deterministic endpoint correlation.</p>
          </div>
          <div className="sidebar-footnote"><span>Analyzer workspace</span><span>v1.0</span></div>
        </div>
      </aside>
    </>
  );
};
