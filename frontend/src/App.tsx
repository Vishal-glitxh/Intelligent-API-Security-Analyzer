import React, { useState, Suspense, lazy } from 'react';
import { AuthProvider } from './context/AuthContext';
import { Sidebar, ScreenId } from './components/common/Sidebar';
import { Header } from './components/common/Header';
import { ShieldAlert, PlusCircle, RefreshCw } from 'lucide-react';

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
  <div className="p-16 text-center flex flex-col items-center justify-center gap-3">
    <RefreshCw className="h-6 w-6 text-teal-400 animate-spin" />
    <span className="text-xs text-slate-400 font-mono">Loading workstation module...</span>
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
    <div className="p-12 bg-slate-900 border border-slate-800 rounded-lg text-center flex flex-col items-center justify-center gap-3">
      <ShieldAlert className="h-8 w-8 text-amber-400" />
      <h3 className="text-sm font-semibold text-slate-200">No Active Scan Selected</h3>
      <p className="text-xs text-slate-400 max-w-sm">
        To view findings, correlation details, or reports, please select an existing scan from the dashboard or launch a new security scan.
      </p>
      <div className="flex items-center gap-3 mt-2">
        <button
          onClick={() => setCurrentScreen('dashboard')}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 rounded border border-slate-700"
        >
          Go to Dashboard
        </button>
        <button
          onClick={() => setCurrentScreen('new-scan')}
          className="flex items-center gap-1.5 px-3.5 py-1.5 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold rounded shadow-xs"
        >
          <PlusCircle className="h-3.5 w-3.5" />
          <span>New Scan</span>
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Sidebar */}
      <Sidebar
        currentScreen={currentScreen}
        onNavigate={handleNavigate}
        selectedScanId={selectedScanId}
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
      />

      {/* Main Content Area */}
      <div className="lg:pl-64 flex flex-col min-h-screen flex-1">
        <Header
          currentScreen={currentScreen}
          selectedScanId={selectedScanId}
          onOpenSidebar={() => setIsSidebarOpen(true)}
          onSelectScan={handleSelectScan}
        />

        {/* Screen View with Suspense */}
        <main className="flex-1 p-4 lg:p-6 overflow-x-hidden">
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
                  onSelectScan={handleSelectScan}
                />
              ) : renderNoScanSelected()
            )}

            {currentScreen === 'findings' && (
              selectedScanId ? (
                <FindingsExplorerScreen
                  scanId={selectedScanId}
                  onNavigate={handleNavigate}
                />
              ) : renderNoScanSelected()
            )}

            {currentScreen === 'correlation' && (
              selectedScanId ? (
                <EndpointCorrelationScreen
                  scanId={selectedScanId}
                  onNavigate={handleNavigate}
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
                  onNavigate={handleNavigate}
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
