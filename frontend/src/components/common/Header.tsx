import React, { useEffect, useState } from 'react';
import { AlertCircle, Check, KeyRound, Menu, RefreshCw } from 'lucide-react';
import { useAuth } from '../../context/useAuth';
import { ApiKeyModal } from './ApiKeyModal';
import { ScreenId } from './Sidebar';

interface HeaderProps {
  currentScreen: ScreenId;
  selectedScanId: string | null;
  onOpenSidebar: () => void;
  onSelectScan: (scanId: string | null) => void;
}

const screenTitles: Record<ScreenId, { title: string; subtitle: string }> = {
  dashboard: { title: 'Overview', subtitle: 'A clear view of your security analysis activity.' },
  'new-scan': { title: 'New assessment', subtitle: 'Analyze an API contract alongside its source code.' },
  'scan-details': { title: 'Scan summary', subtitle: 'Review scan status, metadata, and analysis metrics.' },
  findings: { title: 'Findings explorer', subtitle: 'Investigate evidence across specification, source, and correlation.' },
  correlation: { title: 'Endpoint correlation', subtitle: 'Understand how API contracts align with implementation routes.' },
  research: { title: 'Research benchmarks', subtitle: 'Explore reproducible baseline and external benchmark results.' },
  reports: { title: 'Reports & exports', subtitle: 'Review and export a security assessment.' },
};

export const Header: React.FC<HeaderProps> = ({
  currentScreen,
  selectedScanId,
  onOpenSidebar,
  onSelectScan,
}) => {
  const { isAuthenticated, localDevelopmentAccess } = useAuth();
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [backendStatus, setBackendStatus] = useState<'checking' | 'healthy' | 'offline'>('checking');

  useEffect(() => {
    let isMounted = true;
    const checkHealth = async () => {
      try {
        const response = await fetch('/health');
        if (isMounted) setBackendStatus(response.ok ? 'healthy' : 'offline');
      } catch {
        if (isMounted) setBackendStatus('offline');
      }
    };
    void checkHealth();
    const interval = window.setInterval(checkHealth, 30_000);
    return () => {
      isMounted = false;
      window.clearInterval(interval);
    };
  }, []);

  const meta = screenTitles[currentScreen];

  return (
    <>
      <header className="topbar">
        <div className="topbar-leading">
          <button className="mobile-menu" onClick={onOpenSidebar} aria-label="Open navigation">
            <Menu size={18} />
          </button>
          <div className="min-w-0">
            <div className="topbar-breadcrumb">Security workspace <span aria-hidden="true">/</span> {meta.title}</div>
            <div className="flex min-w-0 items-center gap-2">
              <h1 className="topbar-title">{meta.title}</h1>
              {selectedScanId && ['scan-details', 'findings', 'correlation', 'reports'].includes(currentScreen) && (
                <span className="scan-context-pill" title={selectedScanId}>
                  <span>Scan</span> {selectedScanId.slice(0, 8)}
                  <button
                    type="button"
                    onClick={() => onSelectScan(null)}
                    aria-label="Clear selected scan"
                    title="Clear selected scan"
                  >
                    ×
                  </button>
                </span>
              )}
            </div>
            <p className="topbar-subtitle">{meta.subtitle}</p>
          </div>
        </div>

        <div className="topbar-actions">
          <div className="api-status" title={backendStatus === 'healthy' ? 'Backend API reachable' : 'Backend connection status'}>
            {backendStatus === 'checking' && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
            <span className={`status-indicator ${backendStatus === 'healthy' ? 'online' : backendStatus === 'offline' ? 'offline' : ''}`} />
            <span>{backendStatus === 'healthy' ? 'API connected' : backendStatus === 'offline' ? 'API unavailable' : 'Checking API'}</span>
          </div>
          <button
            type="button"
            className={`credential-button${isAuthenticated ? ' configured' : ''}`}
            onClick={() => setIsKeyModalOpen(true)}
            aria-label={isAuthenticated ? 'Manage API credentials' : 'Configure API credentials'}
          >
            {isAuthenticated ? <Check size={15} /> : <KeyRound size={15} />}
            <span>{localDevelopmentAccess ? 'Local access' : isAuthenticated ? 'Credentials ready' : 'Connect API'}</span>
            {!isAuthenticated && <AlertCircle size={14} />}
          </button>
        </div>
      </header>
      <ApiKeyModal isOpen={isKeyModalOpen} onClose={() => setIsKeyModalOpen(false)} />
    </>
  );
};
