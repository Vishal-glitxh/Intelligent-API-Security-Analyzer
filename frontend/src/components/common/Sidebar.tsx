import React from 'react';
import { 
  LayoutDashboard, 
  PlusCircle, 
  FileSearch, 
  ShieldAlert, 
  GitCompare, 
  FlaskConical, 
  FileText,
  ShieldCheck,
  ChevronRight
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
  onClose
}) => {
  const mainNavItems = [
    {
      id: 'dashboard' as ScreenId,
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: null
    },
    {
      id: 'new-scan' as ScreenId,
      label: 'New Scan',
      icon: PlusCircle,
      badge: null
    },
    {
      id: 'research' as ScreenId,
      label: 'Research Benchmark',
      icon: FlaskConical,
      badge: 'Phase 7.3'
    }
  ];

  const scanScopedItems = [
    {
      id: 'scan-details' as ScreenId,
      label: 'Scan Overview',
      icon: FileSearch
    },
    {
      id: 'findings' as ScreenId,
      label: 'Findings Explorer',
      icon: ShieldAlert
    },
    {
      id: 'correlation' as ScreenId,
      label: 'Endpoint Correlation',
      icon: GitCompare
    },
    {
      id: 'reports' as ScreenId,
      label: 'Reports & Export',
      icon: FileText
    }
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-slate-950/80 z-40 lg:hidden backdrop-blur-xs"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Persistent Sidebar */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 w-64 bg-slate-900 border-r border-slate-800 flex flex-col transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand / Header */}
        <div className="h-16 flex items-center px-5 border-b border-slate-800 gap-3">
          <div className="h-9 w-9 rounded-lg bg-teal-500/10 border border-teal-500/30 flex items-center justify-center text-teal-400">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-semibold text-slate-100 tracking-tight truncate">
              API Security Analyzer
            </span>
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
              Analyst Workstation
            </span>
          </div>
        </div>

        {/* Navigation list */}
        <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
          {/* Main workspace navigation */}
          <div>
            <div className="px-3 mb-2 text-[10px] font-mono uppercase tracking-wider text-slate-500">
              Workspace
            </div>
            <nav className="space-y-1">
              {mainNavItems.map((item) => {
                const Icon = item.icon;
                const isActive = currentScreen === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      onNavigate(item.id);
                      onClose();
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                      isActive
                        ? 'bg-teal-500/10 text-teal-300 border border-teal-500/30'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`}
                  >
                    <Icon className={`h-4 w-4 shrink-0 ${isActive ? 'text-teal-400' : 'text-slate-400'}`} />
                    <span className="flex-1 text-left">{item.label}</span>
                    {item.badge && (
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-teal-400">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Active Scan Context Navigation */}
          <div>
            <div className="px-3 mb-2 flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-slate-500">
              <span>Active Scan Analysis</span>
              {selectedScanId ? (
                <span className="text-slate-400 font-mono text-[9px] truncate max-w-[80px]" title={selectedScanId}>
                  #{selectedScanId.slice(0, 6)}
                </span>
              ) : (
                <span className="text-slate-600 text-[9px]">(None)</span>
              )}
            </div>
            <nav className="space-y-1">
              {scanScopedItems.map((item) => {
                const Icon = item.icon;
                const isActive = currentScreen === item.id;
                const isDisabled = !selectedScanId;

                return (
                  <button
                    key={item.id}
                    disabled={isDisabled}
                    onClick={() => {
                      if (selectedScanId) {
                        onNavigate(item.id, selectedScanId);
                        onClose();
                      }
                    }}
                    title={isDisabled ? 'Select or create a scan first' : item.label}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                      isActive
                        ? 'bg-teal-500/10 text-teal-300 border border-teal-500/30'
                        : isDisabled
                        ? 'text-slate-600 cursor-not-allowed opacity-60'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`}
                  >
                    <Icon className={`h-4 w-4 shrink-0 ${isActive ? 'text-teal-400' : 'text-slate-500'}`} />
                    <span className="flex-1 text-left">{item.label}</span>
                    {selectedScanId && isActive && (
                      <ChevronRight className="h-3 w-3 text-teal-400 shrink-0" />
                    )}
                  </button>
                );
              })}
            </nav>
          </div>
        </div>

        {/* Footer Info */}
        <div className="p-4 border-t border-slate-800 text-[11px] text-slate-500 flex flex-col gap-1 font-mono">
          <div className="flex justify-between items-center text-slate-400">
            <span>Analyzer Core</span>
            <span className="text-teal-400 font-semibold">Phase 8</span>
          </div>
          <div className="text-[10px] text-slate-500 truncate">
            Ground Truth: Frozen 24 + 12
          </div>
        </div>
      </aside>
    </>
  );
};
