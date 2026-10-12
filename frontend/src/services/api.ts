import { Scan, ScanCreateResponse, ScanResultsResponse } from '../types/scan';
import { ScanFindingsResponse } from '../types/findings';
import { ResearchBenchmarksData } from '../types/research';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, message: string, detail?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail || message;
  }
}

function resolveHeaders(customHeaders?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...(customHeaders || {}) };
  if (!headers['X-API-Key'] && !headers['Authorization']) {
    const sessionKey = sessionStorage.getItem('analyzer_session_api_key');
    if (sessionKey) {
      headers['X-API-Key'] = sessionKey;
      headers['Authorization'] = `Bearer ${sessionKey}`;
    }
  }
  return headers;
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = '';
    try {
      const errJson = await response.json();
      detail = errJson.detail || JSON.stringify(errJson);
    } catch {
      detail = await response.text();
    }

    if (response.status === 401) {
      throw new ApiError(401, 'Authentication failed. Please configure a valid API Key in Settings.', detail);
    }
    if (response.status === 403) {
      throw new ApiError(403, 'Access denied. You do not have permission to view or modify this resource.', detail);
    }
    if (response.status === 413) {
      throw new ApiError(413, 'Upload rejected: Payload exceeds maximum size limit (OpenAPI max 5MB, Source ZIP max 25MB).', detail);
    }
    if (response.status === 429) {
      throw new ApiError(429, 'Rate or concurrency limit reached. Please wait before submitting another scan.', detail);
    }

    throw new ApiError(
      response.status,
      `API request failed with HTTP status ${response.status}: ${detail || response.statusText}`,
      detail
    );
  }

  return response.json();
}

export const api = {
  async checkHealth(): Promise<{ status: string }> {
    try {
      const res = await fetch('/health');
      if (!res.ok) throw new Error();
      return await res.json();
    } catch {
      return { status: 'down' };
    }
  },

  async listScans(limitOrHeaders?: number | Record<string, string>, maybeLimit = 50): Promise<Scan[]> {
    let headers: Record<string, string> = {};
    let limit = 50;

    if (typeof limitOrHeaders === 'number') {
      limit = limitOrHeaders;
    } else if (typeof limitOrHeaders === 'object') {
      headers = limitOrHeaders;
      limit = maybeLimit;
    }

    const resolved = resolveHeaders(headers);
    const res = await fetch(`${API_BASE_URL}/scans?limit=${limit}`, {
      headers: {
        Accept: 'application/json',
        ...resolved,
      },
    });
    return handleResponse<Scan[]>(res);
  },

  async getScan(scanId: string, customHeaders?: Record<string, string>): Promise<Scan> {
    const resolved = resolveHeaders(customHeaders);
    const res = await fetch(`${API_BASE_URL}/scans/${scanId}`, {
      headers: {
        Accept: 'application/json',
        ...resolved,
      },
    });
    return handleResponse<Scan>(res);
  },

  async getScanResults(scanId: string, customHeaders?: Record<string, string>): Promise<ScanResultsResponse> {
    const resolved = resolveHeaders(customHeaders);
    const res = await fetch(`${API_BASE_URL}/scans/${scanId}/results`, {
      headers: {
        Accept: 'application/json',
        ...resolved,
      },
    });
    return handleResponse<ScanResultsResponse>(res);
  },

  async getScanFindings(scanId: string, customHeaders?: Record<string, string>): Promise<ScanFindingsResponse> {
    const resolved = resolveHeaders(customHeaders);
    const res = await fetch(`${API_BASE_URL}/scans/${scanId}/findings`, {
      headers: {
        Accept: 'application/json',
        ...resolved,
      },
    });
    return handleResponse<ScanFindingsResponse>(res);
  },

  async createScan(
    fileOrFormData: File | FormData,
    archiveFile?: File,
    projectName?: string,
    customHeaders?: Record<string, string>
  ): Promise<ScanCreateResponse> {
    let formData: FormData;

    if (fileOrFormData instanceof FormData) {
      formData = fileOrFormData;
    } else {
      formData = new FormData();
      formData.append('openapi_file', fileOrFormData);
      if (archiveFile) {
        formData.append('source_archive', archiveFile);
      }
      if (projectName) {
        formData.append('project_name', projectName);
      }
    }

    const resolved = resolveHeaders(customHeaders);
    const res = await fetch(`${API_BASE_URL}/scans`, {
      method: 'POST',
      headers: {
        ...resolved,
      },
      body: formData,
    });
    return handleResponse<ScanCreateResponse>(res);
  },

  async getScanReportJson(scanId: string, customHeaders?: Record<string, string>): Promise<unknown> {
    const resolved = resolveHeaders(customHeaders);
    const res = await fetch(`${API_BASE_URL}/scans/${scanId}/report?format=json`, {
      headers: {
        Accept: 'application/json',
        ...resolved,
      },
    });
    return handleResponse<unknown>(res);
  },

  async getScanReportHtml(scanId: string, customHeaders?: Record<string, string>): Promise<string> {
    const resolved = resolveHeaders(customHeaders);
    const res = await fetch(`${API_BASE_URL}/scans/${scanId}/report?format=html`, {
      headers: {
        Accept: 'text/html',
        ...resolved,
      },
    });
    if (!res.ok) {
      throw new ApiError(res.status, `Report download failed: ${res.statusText}`);
    }
    return res.text();
  },

  async getResearchBenchmarks(customHeaders?: Record<string, string>): Promise<ResearchBenchmarksData> {
    const resolved = resolveHeaders(customHeaders);
    const res = await fetch(`${API_BASE_URL}/research/benchmarks`, {
      headers: {
        Accept: 'application/json',
        ...resolved,
      },
    });
    return handleResponse<ResearchBenchmarksData>(res);
  },
};
