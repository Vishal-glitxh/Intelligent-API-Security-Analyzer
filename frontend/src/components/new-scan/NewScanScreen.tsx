import React, { useState, useRef } from 'react';
import { 
  UploadCloud, 
  FileCode, 
  FileArchive, 
  AlertCircle, 
  CheckCircle2, 
  ArrowRight,
  ShieldAlert,
  Info,
  Loader2
} from 'lucide-react';
import { api } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { ApiKeyModal } from '../common/ApiKeyModal';

// Backend constraints
const MAX_SPEC_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_ARCHIVE_BYTES = 25 * 1024 * 1024; // 25 MB
const MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50 MB

interface NewScanScreenProps {
  onNavigate: (screen: any, scanId?: string) => void;
  onSelectScan: (scanId: string) => void;
}

export const NewScanScreen: React.FC<NewScanScreenProps> = ({
  onNavigate,
  onSelectScan
}) => {
  const { isAuthenticated } = useAuth();
  const [projectName, setProjectName] = useState('');
  const [specFile, setSpecFile] = useState<File | null>(null);
  const [archiveFile, setArchiveFile] = useState<File | null>(null);
  
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);

  const specInputRef = useRef<HTMLInputElement>(null);
  const archiveInputRef = useRef<HTMLInputElement>(null);

  // Client-side validations
  const handleSpecSelect = (file: File) => {
    setValidationError(null);
    setSubmitError(null);
    const validExtensions = ['.json', '.yaml', '.yml'];
    const hasValidExt = validExtensions.some((ext) => file.name.toLowerCase().endsWith(ext));
    
    if (!hasValidExt) {
      setValidationError(`OpenAPI specification must be a .json, .yaml, or .yml file. (Received: ${file.name})`);
      return;
    }

    if (file.size > MAX_SPEC_BYTES) {
      setValidationError(`OpenAPI specification exceeds the 5 MB limit (${(file.size / (1024 * 1024)).toFixed(2)} MB).`);
      return;
    }

    if (file.size === 0) {
      setValidationError(`OpenAPI file is empty (0 bytes).`);
      return;
    }

    setSpecFile(file);
  };

  const handleArchiveSelect = (file: File) => {
    setValidationError(null);
    setSubmitError(null);
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setValidationError(`Source archive must be a .zip file. (Received: ${file.name})`);
      return;
    }

    if (file.size > MAX_ARCHIVE_BYTES) {
      setValidationError(`Source archive exceeds the 25 MB limit (${(file.size / (1024 * 1024)).toFixed(2)} MB).`);
      return;
    }

    if (file.size === 0) {
      setValidationError(`Source archive is empty (0 bytes).`);
      return;
    }

    setArchiveFile(file);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);
    setSubmitError(null);

    if (!specFile) {
      setValidationError('Please select an OpenAPI specification file.');
      return;
    }

    if (!archiveFile) {
      setValidationError('Please select a source code ZIP archive.');
      return;
    }

    if (specFile.size + archiveFile.size > MAX_TOTAL_BYTES) {
      setValidationError('Total upload payload exceeds the 50 MB server limit.');
      return;
    }

    if (!isAuthenticated) {
      setIsKeyModalOpen(true);
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await api.createScan(specFile, archiveFile, projectName.trim() || undefined);
      const createdId = response.scan_id || response.id || '';
      onSelectScan(createdId);
      onNavigate('scan-details', createdId);
    } catch (err: any) {
      setSubmitError(err.message || 'Failed to submit security scan.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Intro card */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-lg">
        <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
          <UploadCloud className="h-5 w-5 text-teal-400" />
          <span>Initiate Dual-Layer API Security Analysis</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Upload your API specification alongside application source code. The analyzer will perform spec-level rule checking, AST/regex source scanning, and deterministic endpoint correlation.
        </p>

        {/* Limit notice */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">OpenAPI Specification</span>
            <span className="text-teal-400 font-semibold">Max 5 MB</span>
            <span className="text-slate-500 block text-[10px]">.json, .yaml, .yml</span>
          </div>
          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Source Code Archive</span>
            <span className="text-teal-400 font-semibold">Max 25 MB</span>
            <span className="text-slate-500 block text-[10px]">.zip archive</span>
          </div>
          <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Total Payload Ceiling</span>
            <span className="text-teal-400 font-semibold">Max 50 MB</span>
            <span className="text-slate-500 block text-[10px]">Enforced by gateway</span>
          </div>
        </div>
      </div>

      {/* Form Card */}
      <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 p-6 rounded-lg space-y-6">
        {/* Project Name Field */}
        <div>
          <label className="block text-xs font-mono uppercase text-slate-300 mb-1.5">
            Project / Application Name (Optional)
          </label>
          <input
            type="text"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            placeholder="e.g. Payments Service v2, VAmPI Target"
            className="w-full bg-slate-950 border border-slate-800 focus:border-teal-500 focus:ring-1 focus:ring-teal-500 rounded-md px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 transition-colors"
          />
        </div>

        {/* Upload Targets Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Spec File Selector */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-300 mb-1.5">
              1. OpenAPI Specification <span className="text-rose-400">*</span>
            </label>
            <input
              type="file"
              ref={specInputRef}
              accept=".json,.yaml,.yml"
              onChange={(e) => {
                if (e.target.files?.[0]) handleSpecSelect(e.target.files[0]);
              }}
              className="hidden"
            />
            <div
              onClick={() => specInputRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (e.dataTransfer.files?.[0]) handleSpecSelect(e.dataTransfer.files[0]);
              }}
              className={`border-2 border-dashed rounded-lg p-5 text-center cursor-pointer transition-colors ${
                specFile
                  ? 'border-teal-500/50 bg-teal-500/5'
                  : 'border-slate-800 hover:border-slate-700 bg-slate-950/40'
              }`}
            >
              {specFile ? (
                <div className="space-y-2">
                  <div className="h-10 w-10 mx-auto rounded-full bg-teal-500/10 text-teal-400 flex items-center justify-center">
                    <CheckCircle2 className="h-5 w-5" />
                  </div>
                  <div className="text-xs font-medium text-slate-200 truncate">{specFile.name}</div>
                  <div className="text-[11px] font-mono text-slate-400">
                    {(specFile.size / 1024).toFixed(1)} KB
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSpecFile(null);
                    }}
                    className="text-[11px] text-slate-500 hover:text-rose-400 underline"
                  >
                    Change file
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  <FileCode className="h-8 w-8 mx-auto text-slate-500" />
                  <div className="text-xs font-medium text-slate-300">
                    Click to browse or drop OpenAPI file
                  </div>
                  <div className="text-[11px] text-slate-500">Supports JSON, YAML, or YML (up to 5MB)</div>
                </div>
              )}
            </div>
          </div>

          {/* Source Archive Selector */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-300 mb-1.5">
              2. Source Code Archive <span className="text-rose-400">*</span>
            </label>
            <input
              type="file"
              ref={archiveInputRef}
              accept=".zip"
              onChange={(e) => {
                if (e.target.files?.[0]) handleArchiveSelect(e.target.files[0]);
              }}
              className="hidden"
            />
            <div
              onClick={() => archiveInputRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (e.dataTransfer.files?.[0]) handleArchiveSelect(e.dataTransfer.files[0]);
              }}
              className={`border-2 border-dashed rounded-lg p-5 text-center cursor-pointer transition-colors ${
                archiveFile
                  ? 'border-teal-500/50 bg-teal-500/5'
                  : 'border-slate-800 hover:border-slate-700 bg-slate-950/40'
              }`}
            >
              {archiveFile ? (
                <div className="space-y-2">
                  <div className="h-10 w-10 mx-auto rounded-full bg-teal-500/10 text-teal-400 flex items-center justify-center">
                    <CheckCircle2 className="h-5 w-5" />
                  </div>
                  <div className="text-xs font-medium text-slate-200 truncate">{archiveFile.name}</div>
                  <div className="text-[11px] font-mono text-slate-400">
                    {(archiveFile.size / (1024 * 1024)).toFixed(2)} MB
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setArchiveFile(null);
                    }}
                    className="text-[11px] text-slate-500 hover:text-rose-400 underline"
                  >
                    Change archive
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  <FileArchive className="h-8 w-8 mx-auto text-slate-500" />
                  <div className="text-xs font-medium text-slate-300">
                    Click to browse or drop ZIP archive
                  </div>
                  <div className="text-[11px] text-slate-500">FastAPI, Flask, or Express source (up to 25MB)</div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Validation or API Errors */}
        {validationError && (
          <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-md flex items-start gap-2.5 text-xs text-amber-300">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
            <span>{validationError}</span>
          </div>
        )}

        {submitError && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-md flex items-start gap-2.5 text-xs text-rose-300">
            <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5 text-rose-400" />
            <div className="space-y-1">
              <span className="font-semibold block">Submission Error:</span>
              <span className="font-mono">{submitError}</span>
            </div>
          </div>
        )}

        {/* Auth Notice */}
        {!isAuthenticated && (
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-md flex items-center justify-between gap-3 text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-teal-400 shrink-0" />
              <span>An API Key is required to authorize scan submission with client ownership.</span>
            </div>
            <button
              type="button"
              onClick={() => setIsKeyModalOpen(true)}
              className="text-teal-400 hover:text-teal-300 font-medium underline shrink-0"
            >
              Enter API Key
            </button>
          </div>
        )}

        {/* Submit Button */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            type="submit"
            disabled={isSubmitting || !specFile || !archiveFile}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-md text-xs font-semibold transition-colors shadow-xs ${
              isSubmitting || !specFile || !archiveFile
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                : 'bg-teal-500 hover:bg-teal-400 text-slate-950 cursor-pointer'
            }`}
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Uploading & Starting Scan...</span>
              </>
            ) : (
              <>
                <span>Launch Security Analysis</span>
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        </div>
      </form>

      <ApiKeyModal
        isOpen={isKeyModalOpen}
        onClose={() => setIsKeyModalOpen(false)}
      />
    </div>
  );
};
