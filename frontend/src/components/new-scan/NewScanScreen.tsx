import React, { useState, useRef, useEffect } from 'react';
import { 
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
import { useAuth } from '../../context/useAuth';
import { ApiKeyModal } from '../common/ApiKeyModal';
import { LocalAIStatus } from '../../types/findings';

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
  const [localAIStatus, setLocalAIStatus] = useState<LocalAIStatus | null>(null);
  const visibleLocalAIStatus = isAuthenticated ? localAIStatus : null;
  
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);

  const specInputRef = useRef<HTMLInputElement>(null);
  const archiveInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!isAuthenticated) return;
    let active = true;
    void api.getLocalAIStatus().then((result) => {
      if (active) setLocalAIStatus(result);
    }).catch(() => {
      if (active) setLocalAIStatus(null);
    });
    return () => { active = false; };
  }, [isAuthenticated]);

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

    if (specFile.size + (archiveFile?.size ?? 0) > MAX_TOTAL_BYTES) {
      setValidationError('Total upload payload exceeds the 50 MB server limit.');
      return;
    }

    if (!isAuthenticated) {
      setIsKeyModalOpen(true);
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await api.createScan(specFile, archiveFile ?? undefined, projectName.trim() || undefined);
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
    <div className="upload-page">
      <section className="upload-intro">
        <div className="page-eyebrow"><span className="page-eyebrow-mark" /> New assessment <span aria-hidden="true">·</span> static analysis</div>
        <h2 className="page-heading">Bring your API into focus.</h2>
        <p className="page-description">Analyze an OpenAPI contract on its own, or add a source archive to compare implementation evidence. The scan reports specification, source, and correlated results where available.</p>

        <div className="upload-limit-grid">
          <div className="upload-limit">
            <span className="upload-limit-label">OpenAPI specification</span>
            <span className="upload-limit-value">Up to 5 MB</span>
            <span className="upload-limit-hint">JSON or YAML</span>
          </div>
          <div className="upload-limit">
            <span className="upload-limit-label">Source code archive</span>
            <span className="upload-limit-value">Up to 25 MB</span>
            <span className="upload-limit-hint">ZIP archive</span>
          </div>
          <div className="upload-limit">
            <span className="upload-limit-label">Request size ceiling</span>
            <span className="upload-limit-value">Up to 50 MB</span>
            <span className="upload-limit-hint">Enforced by the API</span>
          </div>
        </div>
      </section>

      <form onSubmit={handleSubmit} className="surface-card upload-form">
        <div>
          <label htmlFor="project-name" className="form-label">
            Project name <span className="font-normal text-slate-500">· optional</span>
          </label>
          <input
            id="project-name"
            type="text"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            maxLength={120}
            placeholder="For example, Payments API"
          />
        </div>

        <div className="upload-target-grid">
          <div>
            <label htmlFor="openapi-upload" className="upload-target-label">
              <span className="upload-step">01</span> OpenAPI specification <span className="text-rose-400">*</span>
            </label>
            <input
              id="openapi-upload"
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
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  specInputRef.current?.click();
                }
              }}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (e.dataTransfer.files?.[0]) handleSpecSelect(e.dataTransfer.files[0]);
              }}
              role="button"
              tabIndex={0}
              aria-label="Choose or drop an OpenAPI specification"
              className={`upload-dropzone${specFile ? ' has-file' : ''}`}
            >
              {specFile ? (
                <>
                  <span className="dropzone-icon"><CheckCircle2 size={19} /></span>
                  <span className="dropzone-title">{specFile.name}</span>
                  <span className="dropzone-hint">{(specFile.size / 1024).toFixed(1)} KB · click to replace</span>
                </>
              ) : (
                <>
                  <span className="dropzone-icon"><FileCode size={20} /></span>
                  <span className="dropzone-title">Drop your API contract here</span>
                  <span className="dropzone-hint"><span className="dropzone-browse">Browse files</span> · JSON or YAML · up to 5 MB</span>
                </>
              )}
            </div>
          </div>

          <div>
            <label htmlFor="source-archive-upload" className="upload-target-label">
              <span className="upload-step">02</span> Source code archive <span className="font-normal text-slate-500">· optional</span>
            </label>
            <input
              id="source-archive-upload"
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
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  archiveInputRef.current?.click();
                }
              }}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (e.dataTransfer.files?.[0]) handleArchiveSelect(e.dataTransfer.files[0]);
              }}
              role="button"
              tabIndex={0}
              aria-label="Choose or drop a source code ZIP archive"
              className={`upload-dropzone${archiveFile ? ' has-file' : ''}`}
            >
              {archiveFile ? (
                <>
                  <span className="dropzone-icon"><CheckCircle2 size={19} /></span>
                  <span className="dropzone-title">{archiveFile.name}</span>
                  <span className="dropzone-hint">{(archiveFile.size / (1024 * 1024)).toFixed(2)} MB · click to replace</span>
                </>
              ) : (
                <>
                  <span className="dropzone-icon"><FileArchive size={20} /></span>
                  <span className="dropzone-title">Drop your source archive here</span>
                  <span className="dropzone-hint"><span className="dropzone-browse">Browse files</span> · ZIP · up to 25 MB</span>
                </>
              )}
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs">
          <div className="flex items-center justify-between gap-3">
            <span className="font-medium text-slate-200">Local AI explanations</span>
            <span className={`rounded-full px-2 py-1 text-[10px] font-semibold ${visibleLocalAIStatus?.status === 'Available' ? 'bg-emerald-950 text-emerald-300' : 'bg-slate-800 text-slate-400'}`}>
              {visibleLocalAIStatus?.status ?? (isAuthenticated ? 'Checking' : 'Configure access to check')}
            </span>
          </div>
          <p className="mt-1 text-slate-400">
            {visibleLocalAIStatus?.message ?? 'Scans use deterministic analysis without a hosted AI key. Ollama is optional.'}
            {visibleLocalAIStatus?.model_name ? ` Model: ${visibleLocalAIStatus.model_name}.` : ''}
          </p>
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
        <div className="upload-submit-row">
          <p className="upload-helper"><ShieldAlert size={15} /> Source files are inspected statically and are never executed. All scans include every applicable analysis layer.</p>
          <button
            type="submit"
            disabled={isSubmitting || !specFile}
            className="button button-primary"
            aria-live="polite"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Uploading and analyzing…</span>
              </>
            ) : (
              <>
                <span>Start assessment</span>
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
