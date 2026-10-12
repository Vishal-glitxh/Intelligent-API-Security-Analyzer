import React, { useState, useEffect } from 'react';
import { Menu, Key, CheckCircle2, AlertCircle, RefreshCw, Layers } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { ApiKeyModal } from './ApiKeyModal';
import { ScreenId } from './Sidebar';

interface HeaderProps {
  currentScreen: ScreenId;
  selectedScanId: string | null;
  onOpenSidebar: () => void;
  onSelectScan: (scanId: string | null) => void;
}

const screenTitles: Record<ScreenId, { title: string; subtitle: string }> = {
  dashboard: {
    title: 'Analyst Dashboard',
    subtitle: 'Telemetry, recent analysis runs, and findings breakdown'
  },
  'new-scan': {
    title: 'New API Security Scan',
    subtitle: 'Upload OpenAPI specifications and source code archives for correlation'
  },
  'scan-details': {
    title: 'Scan Lifecycle & Metadata',
    subtitle: 'Execution status, lifecycle timestamps, and run metrics'
  },
  findings: {
    title: 'Security Findings Explorer',
    subtitle: 'Inspect and filter findings across Spec, Source, and Correlated layers'
  },
  correlation: {
    title: 'Endpoint & Correlation Explorer',
    subtitle: 'Trace endpoint parity and multi-evidence verification matrices'
  },
  research: {
    title: 'Research & External Benchmark',
    subtitle: 'Compare baseline benchmark (24 cases) against VAmPI benchmark (12 cases)'
  },
  reports: {
    title: 'Security Assessment Reports',
    subtitle: 'Inspect and export structured JSON and executive HTML vulnerability audits'
  }
};

export const Header: React.FC<HeaderProps> = ({
  currentScreen,
  selectedScanId,
  onOpenSidebar,
  onSelectScan
}) => {
  const { isAuthenticated, apiKey } = useAuth();
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [backendStatus, setBackendStatus] = useState<'checking' | 'healthy' | 'offline'>('checking');

  // Check health periodically
  useEffect(() => {
    let isMounted = true;
    const checkHealth = async () => {
      try {
        const res = await fetch('/health');
        if (res.ok && isMounted) {
          setBackendStatus('healthy');
        } else if (isMounted) {
          setBackendStatus('offline');
        }
      } catch {
        if (isMounted) setBackendStatus('offline');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const meta = screenTitles[currentScreen] || {
    title: 'API Security Analyzer',
    subtitle: 'Analyst Workstation'
  };

  return (
    <>
      <header className="h-16 bg-slate-900/90 border-b border-slate-800 px-4 lg:px-6 flex items-center justify-between sticky top-0 z-30 backdrop-blur-md">
        {/* Left: Mobile hamburger & Titles */}
        <div className="flex items-center gap-4 min-w-0">
          <button
            onClick={onOpenSidebar}
            className="lg:hidden p-2 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800"
            aria-label="Open sidebar"
          >
            <Menu className="h-5 w-5" />
          </button>

          <div className="flex flex-col min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-base font-semibold text-slate-100 truncate">
                {meta.title}
              </h1>
              {selectedScanId && ['scan-details', 'findings', 'correlation', 'reports'].includes(currentScreen) && (
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-teal-500/10 border border-teal-500/30 text-teal-300 text-xs font-mono">
                  <Layers className="h-3 w-3" />
                  <span className="truncate max-w-[140px]" title={selectedScanId}>
                    {selectedScanId.slice(0, 8)}...
                  </span>
                  <button 
                    onClick={() => onSelectScan(null)}
                    className="text-slate-500 hover:text-slate-300 ml-1"
                    title="Deselect scan"
                  >
                    ×
                  </button>
                </div>
              )}
            </div>
            <p className="text-xs text-slate-400 hidden sm:block truncate">
              {meta.subtitle}
            </p>
          </div>
        </div>

        {/* Right: Backend indicator & Auth Key status */}
        <div className="flex items-center gap-3">
          {/* Backend Status indicator */}
          <div 
            className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border"
            title={backendStatus === 'healthy' ? 'Backend API reachable' : 'Backend connection failed'}
          >
            {backendStatus === 'checking' && (
              <>
                <RefreshCw className="h-3 w-3 text-slate-400 animate-spin" />
                <span className="text-slate-400 text-[11px]">Connecting</span>
              </>
            )}
            {backendStatus === 'healthy' && (
              <>
                <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-emerald-400 text-[11px]">API Online</span>
              </>
            )}
            {backendStatus === 'offline' && (
              <>
                <span className="h-2 w-2 rounded-full bg-amber-500" />
                <span className="text-amber-400 text-[11px]">API Offline</span>
              </>
            )}
          </div>

          {/* API Key Config Button */}
          <button
            onClick={() => setIsKeyModalOpen(true)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium border transition-colors ${
              isAuthenticated
                ? 'bg-slate-800/80 border-slate-700 text-slate-200 hover:bg-slate-800 hover:border-slate-600'
                : 'bg-amber-500/10 border-amber-500/30 text-amber-300 hover:bg-amber-500/20'
            }`}
          >
            <Key className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">
              {isAuthenticated ? 'API Key Configured' : 'Configure API Key'}
            </span>
            <span className="sm:hidden">
              {isAuthenticated ? 'Key Set' : 'Set Key'}
            </span>
            {isAuthenticated ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" />
            ) : (
              <AlertCircle className="h-3.5 w-3.5 text-amber-400" />
            )}
          </button>
        </div>
      </header>

      {/* API Key Modal */}
      <ApiKeyModal
        isOpen={isKeyModalOpen}
        onClose={() => setIsKeyModalOpen(false)}
      />
    </>
  );
};
