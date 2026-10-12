import { describe, it, expect } from 'vitest';

const MAX_SPEC_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_ARCHIVE_BYTES = 25 * 1024 * 1024; // 25 MB
const MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50 MB

function validateUpload(specName: string, specSize: number, archiveName: string, archiveSize: number) {
  const validSpecExts = ['.json', '.yaml', '.yml'];
  const hasValidSpecExt = validSpecExts.some((ext) => specName.toLowerCase().endsWith(ext));
  if (!hasValidSpecExt) {
    return { valid: false, error: 'OpenAPI specification must be a .json, .yaml, or .yml file.' };
  }
  if (specSize > MAX_SPEC_BYTES) {
    return { valid: false, error: 'OpenAPI specification exceeds the 5 MB limit.' };
  }
  if (specSize === 0) {
    return { valid: false, error: 'OpenAPI specification file is empty.' };
  }

  if (!archiveName.toLowerCase().endsWith('.zip')) {
    return { valid: false, error: 'Source archive must be a .zip file.' };
  }
  if (archiveSize > MAX_ARCHIVE_BYTES) {
    return { valid: false, error: 'Source archive exceeds the 25 MB limit.' };
  }
  if (archiveSize === 0) {
    return { valid: false, error: 'Source archive file is empty.' };
  }

  if (specSize + archiveSize > MAX_TOTAL_BYTES) {
    return { valid: false, error: 'Total upload payload exceeds the 50 MB server limit.' };
  }

  return { valid: true, error: null };
}

describe('Upload Validation Rules', () => {
  it('accepts valid YAML spec and ZIP archive within size limits', () => {
    const res = validateUpload('openapi.yaml', 100 * 1024, 'source.zip', 5 * 1024 * 1024);
    expect(res.valid).toBe(true);
    expect(res.error).toBeNull();
  });

  it('accepts valid JSON spec', () => {
    const res = validateUpload('spec.json', 500 * 1024, 'repo.zip', 1 * 1024 * 1024);
    expect(res.valid).toBe(true);
  });

  it('rejects invalid spec file extensions like .txt or .py', () => {
    const res = validateUpload('openapi.txt', 100, 'source.zip', 1000);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('OpenAPI specification must be a .json, .yaml, or .yml file');
  });

  it('rejects non-zip source archives', () => {
    const res = validateUpload('openapi.yaml', 100, 'source.tar.gz', 1000);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('Source archive must be a .zip file');
  });

  it('rejects OpenAPI specs exceeding 5 MB limit', () => {
    const res = validateUpload('openapi.yaml', 6 * 1024 * 1024, 'source.zip', 1000);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('5 MB limit');
  });

  it('rejects source archives exceeding 25 MB limit', () => {
    const res = validateUpload('openapi.yaml', 1000, 'source.zip', 26 * 1024 * 1024);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('25 MB limit');
  });

  it('rejects empty (0 byte) files', () => {
    const res1 = validateUpload('openapi.yaml', 0, 'source.zip', 1000);
    expect(res1.valid).toBe(false);

    const res2 = validateUpload('openapi.yaml', 1000, 'source.zip', 0);
    expect(res2.valid).toBe(false);
  });
});
