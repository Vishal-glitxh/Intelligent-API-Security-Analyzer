import React, { useState, Suspense, lazy } from 'react';
import { AuthProvider } from './context/AuthContext';
import { Sidebar, ScreenId } from './components/common/Sidebar';
import { Header } from './components/common/Header';
import { ArrowRight, RefreshCw, ShieldCheck } from 'lucide-react';

// Lazy-loaded screen components for efficient code-splitting
const DashboardScreen = lazy(() =>
  import('./components/dashboard/DashboardScreen').then((m) => ({ default: m.DashboardScreen }))
);
const NewScanScreen = lazy(() =>
  import('./components/new-scan/NewScanScreen').then((m) => ({ default: m.NewScanScreen }))
);
const ScanDetailsScreen = lazy(() =>
  import('./components/scan-details/ScanDetailsScreen').then((m) => ({ default: m.ScanDetailsScreen }))
);
const FindingsExplorerScreen = lazy(() =>
  import('./components/findings/FindingsExplorerScreen').then((m) => ({ default: m.FindingsExplorerScreen }))
);
const EndpointCorrelationScreen = lazy(() =>
  import('./components/correlation/EndpointCorrelationScreen').then((m) => ({ default: m.EndpointCorrelationScreen }))
);
const ResearchDashboardScreen = lazy(() =>
  import('./components/research/ResearchDashboardScreen').then((m) => ({ default: m.ResearchDashboardScreen }))
);
const ReportsScreen = lazy(() =>
  import('./components/reports/ReportsScreen').then((m) => ({ default: m.ReportsScreen }))
);

const ScreenLoader: React.FC = () => (
  <div className="screen-loader" role="status" aria-live="polite">
    <span className="loader-icon"><RefreshCw className="h-5 w-5 animate-spin" /></span>
    <span>Preparing your security workspace</span>
  </div>
);

function MainApp() {
  const [currentScreen, setCurrentScreen] = useState<ScreenId>('dashboard');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const handleNavigate = (screen: ScreenId, scanId?: string) => {
    if (scanId) {
      setSelectedScanId(scanId);
    }
    setCurrentScreen(screen);
  };

  const handleSelectScan = (scanId: string | null) => {
    setSelectedScanId(scanId);
  };

  // Helper for scan-dependent screens when no scan is selected
  const renderNoScanSelected = () => (
    <div className="empty-state page-empty-state">
      <span className="empty-state-icon"><ShieldCheck className="h-6 w-6" /></span>
      <h3>No scan selected</h3>
      <p>Choose a scan from your dashboard to explore its findings and report, or start a new security assessment.</p>
      <div className="flex items-center gap-3 mt-2">
        <button
          onClick={() => setCurrentScreen('dashboard')}
          className="button button-secondary"
        >
          Go to Dashboard
        </button>
        <button
          onClick={() => setCurrentScreen('new-scan')}
          className="button button-primary"
        >
          Start a scan <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <Sidebar
        currentScreen={currentScreen}
        onNavigate={handleNavigate}
        selectedScanId={selectedScanId}
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
      />

      {/* Main Content Area */}
      <div className="app-main">
        <Header
          currentScreen={currentScreen}
          selectedScanId={selectedScanId}
          onOpenSidebar={() => setIsSidebarOpen(true)}
          onSelectScan={handleSelectScan}
        />

        {/* Screen View with Suspense */}
        <main className="app-content">
          <Suspense fallback={<ScreenLoader />}>
            {currentScreen === 'dashboard' && (
              <DashboardScreen
                onNavigate={handleNavigate}
                onSelectScan={handleSelectScan}
              />
            )}

            {currentScreen === 'new-scan' && (
              <NewScanScreen
                onNavigate={handleNavigate}
                onSelectScan={handleSelectScan}
              />
            )}

            {currentScreen === 'scan-details' && (
              selectedScanId ? (
                <ScanDetailsScreen
                  scanId={selectedScanId}
                  onNavigate={handleNavigate}
                />
              ) : renderNoScanSelected()
            )}

            {currentScreen === 'findings' && (
              selectedScanId ? (
                <FindingsExplorerScreen
                  scanId={selectedScanId}
                />
              ) : renderNoScanSelected()
            )}

            {currentScreen === 'correlation' && (
              selectedScanId ? (
                <EndpointCorrelationScreen
                  scanId={selectedScanId}
                />
              ) : renderNoScanSelected()
            )}

            {currentScreen === 'research' && (
              <ResearchDashboardScreen />
            )}

            {currentScreen === 'reports' && (
              selectedScanId ? (
                <ReportsScreen
                  scanId={selectedScanId}
                />
              ) : renderNoScanSelected()
            )}
          </Suspense>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}
