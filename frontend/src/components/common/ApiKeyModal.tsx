import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Key, Shield, CheckCircle2, AlertCircle, Eye, EyeOff, X } from 'lucide-react';
import { api } from '../../services/api';

interface ApiKeyModalProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const ApiKeyModal: React.FC<ApiKeyModalProps> = ({ isOpen: propIsOpen, onClose: propOnClose }) => {
  const { apiKey, setApiKey, isConfigModalOpen, setIsConfigModalOpen, clearAuth } = useAuth();
  const [inputVal, setInputVal] = useState(apiKey);
  const [showKey, setShowKey] = useState(false);
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [testMessage, setTestMessage] = useState('');

  const isOpen = propIsOpen !== undefined ? propIsOpen : isConfigModalOpen;
  const handleClose = propOnClose || (() => setIsConfigModalOpen(false));

  if (!isOpen) return null;

  const handleSave = () => {
    setApiKey(inputVal);
    handleClose();
  };

  const handleTest = async () => {
    setTestStatus('testing');
    try {
      const health = await api.checkHealth();
      if (health.status === 'ok') {
        setTestStatus('success');
        setTestMessage('Backend reachable on port 8000.');
      } else {
        setTestStatus('error');
        setTestMessage('Backend returned unexpected status.');
      }
    } catch {
      setTestStatus('error');
      setTestMessage('Could not connect to backend server at http://localhost:8000.');
    }
  };

  const handleUseDevKey = () => {
    const devKey = 'dev-insecure-api-access-token-do-not-use-in-production';
    setInputVal(devKey);
    setApiKey(devKey);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-lg shadow-2xl p-6 text-slate-100">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Key className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-slate-100">API Credentials</h2>
          </div>
          <button
            onClick={handleClose}
            className="p-1 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="mt-4 space-y-4">
          <p className="text-xs text-slate-400 leading-relaxed">
            Provide the API access token configured in the analyzer backend. Protected scan operations require client authentication.
          </p>

          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 flex items-center justify-between">
              <span>X-API-Key / Bearer Token</span>
              <button
                type="button"
                onClick={handleUseDevKey}
                className="text-xs text-cyan-400 hover:underline cursor-pointer"
              >
                Use Dev Token
              </button>
            </label>
            <div className="relative">
              <input
                type={showKey ? 'text' : 'password'}
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                placeholder="Enter API token..."
                className="w-full px-3 py-2 pr-10 text-xs font-mono bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-600 focus:outline-hidden focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
              />
              <button
                type="button"
                onClick={() => setShowKey(!showKey)}
                className="absolute right-2 top-2 text-slate-500 hover:text-slate-300"
              >
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/80 rounded p-3 text-xs space-y-2">
            <div className="flex items-center gap-2 text-slate-300 font-medium">
              <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>In-Memory Security Boundary</span>
            </div>
            <p className="text-slate-400 text-2xs leading-normal">
              Tokens are held in session state for active requests and never written to permanent disk storage.
            </p>
          </div>

          {testStatus !== 'idle' && (
            <div
              className={`p-2.5 rounded text-xs flex items-center gap-2 ${
                testStatus === 'success'
                  ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
                  : testStatus === 'error'
                  ? 'bg-rose-950/60 text-rose-300 border border-rose-800'
                  : 'bg-slate-800 text-slate-300'
              }`}
            >
              {testStatus === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
              {testStatus === 'error' && <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />}
              <span>{testMessage || 'Testing connection...'}</span>
            </div>
          )}
        </div>

        <div className="mt-6 flex items-center justify-between pt-4 border-t border-slate-800">
          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleTest}
              disabled={testStatus === 'testing'}
              className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition disabled:opacity-50"
            >
              Test Backend
            </button>
            {apiKey && (
              <button
                type="button"
                onClick={() => {
                  clearAuth();
                  setInputVal('');
                }}
                className="px-3 py-1.5 text-xs text-rose-400 hover:bg-rose-950/40 rounded transition"
              >
                Clear
              </button>
            )}
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleClose}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              className="px-4 py-1.5 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded transition"
            >
              Save Key
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
