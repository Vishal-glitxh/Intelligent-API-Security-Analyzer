import React, { useState, useEffect, useCallback } from 'react';
import { 
  FileText, 
  Download, 
  Eye, 
  Code, 
  RefreshCw, 
  AlertCircle
} from 'lucide-react';
import { api } from '../../services/api';
import { redactSecrets } from '../../utils/redact';

interface ReportsScreenProps {
  scanId: string;
}

export const ReportsScreen: React.FC<ReportsScreenProps> = ({ scanId }) => {
  const [activeFormat, setActiveFormat] = useState<'html' | 'json'>('html');
  const [htmlContent, setHtmlContent] = useState<string | null>(null);
  const [jsonContent, setJsonContent] = useState<unknown | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<'html' | 'json' | null>(null);

  const fetchReports = useCallback(async () => {
    try {
      if (activeFormat === 'html') {
        const html = await api.getScanReportHtml(scanId);
        setHtmlContent(html);
      } else {
        const json = await api.getScanReportJson(scanId);
        setJsonContent(json);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve assessment report.');
    } finally {
      setLoading(false);
    }
  }, [activeFormat, scanId]);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect -- This starts an API request; its state updates run after the request settles.
    void fetchReports();
  }, [fetchReports]);

  const refreshReports = () => {
    setLoading(true);
    setError(null);
    void fetchReports();
  };

  const handleDownload = async (format: 'html' | 'json') => {
    setDownloading(format);
    try {
      if (format === 'html') {
        const html = htmlContent || (await api.getScanReportHtml(scanId));
        const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-report-${scanId.slice(0, 8)}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else {
        const json = jsonContent || (await api.getScanReportJson(scanId));
        const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-report-${scanId.slice(0, 8)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      alert(`Download failed: ${err.message || 'Unknown error'}`);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <FileText className="h-5 w-5 text-teal-400" />
            <span>Security Assessment Audit Report</span>
          </h2>
          <p className="text-xs text-slate-400">
            Export or inspect cryptographic and deterministic audit findings for Scan #{scanId.slice(0, 8)}.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={() => handleDownload('json')}
            disabled={downloading === 'json'}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono font-medium rounded-md transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            <span>{downloading === 'json' ? 'Downloading...' : 'Export JSON'}</span>
          </button>

          <button
            onClick={() => handleDownload('html')}
            disabled={downloading === 'html'}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-medium rounded-md font-mono shadow-xs transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            <span>{downloading === 'html' ? 'Downloading...' : 'Export HTML'}</span>
          </button>
        </div>
      </div>

      {/* Format Toggle Tabs */}
      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 px-4 py-2.5 rounded-lg text-xs font-mono">
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded border border-slate-800">
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              setActiveFormat('html');
            }}
            className={`flex items-center gap-1.5 px-3 py-1 rounded transition-colors ${
              activeFormat === 'html'
                ? 'bg-teal-500/20 text-teal-300 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Eye className="h-3.5 w-3.5" />
            <span>Executive HTML Report</span>
          </button>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              setActiveFormat('json');
            }}
            className={`flex items-center gap-1.5 px-3 py-1 rounded transition-colors ${
              activeFormat === 'json'
                ? 'bg-teal-500/20 text-teal-300 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code className="h-3.5 w-3.5" />
            <span>Structured JSON Schema</span>
          </button>
        </div>

        <button
          onClick={refreshReports}
          className="p-1.5 text-slate-400 hover:text-slate-200 rounded"
          title="Refresh report content"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Loading */}
      {loading && (
        <div className="p-16 text-center flex flex-col items-center justify-center gap-3">
          <RefreshCw className="h-6 w-6 text-teal-400 animate-spin" />
          <p className="text-xs text-slate-400 font-mono">Compiling {activeFormat.toUpperCase()} report view...</p>
        </div>
      )}

      {/* Error */}
      {!loading && error && (
        <div className="p-8 bg-slate-900 border border-slate-800 rounded-lg text-center flex flex-col items-center justify-center gap-3">
          <AlertCircle className="h-6 w-6 text-rose-400" />
          <p className="text-sm font-semibold text-slate-200">Unable to generate report view</p>
          <p className="text-xs text-slate-400 max-w-md font-mono">{error}</p>
        </div>
      )}

      {/* HTML Viewer (Sandbox iframe) */}
      {!loading && !error && activeFormat === 'html' && htmlContent && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-inner">
          <iframe
            srcDoc={htmlContent}
            title="Executive Security Report"
            className="w-full h-[700px] bg-white border-0"
            sandbox=""
          />
        </div>
      )}

      {/* JSON Viewer */}
      {!loading && !error && activeFormat === 'json' && jsonContent !== null && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="bg-slate-950 border border-slate-800 rounded-md p-4 overflow-x-auto max-h-[700px] font-mono text-xs text-slate-300">
            <pre className="whitespace-pre-wrap">
              {redactSecrets(JSON.stringify(jsonContent, null, 2))}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
