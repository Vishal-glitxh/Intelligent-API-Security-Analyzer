import { describe, it, expect, beforeEach } from 'vitest';
import { redactSecrets } from '../utils/redact';

describe('Secret Redaction Utility', () => {
  it('redacts Bearer tokens in headers and strings', () => {
    const raw = 'Authorization: Bearer secret_token_xyz123456789';
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain('secret_token_xyz123456789');
    expect(redacted).toContain('Bearer [REDACTED]');
  });

  it('redacts password and secret fields in JSON snippets', () => {
    const raw = JSON.stringify({
      password: 'super_secret_password_123',
      api_key: 'sk_live_987654321',
      token: 'jwt.token.abc',
      normal_field: 'safe_value'
    });
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain('super_secret_password_123');
    expect(redacted).not.toContain('sk_live_987654321');
    expect(redacted).toContain('safe_value');
  });

  it('preserves non-sensitive strings intact', () => {
    const raw = 'GET /api/v1/users/profile - Missing authentication requirement in OpenAPI declaration';
    expect(redactSecrets(raw)).toBe(raw);
  });
});

describe('Authentication Header Generation', () => {
  function getAuthHeaders(apiKey: string): Record<string, string> {
    if (!apiKey) return {};
    return {
      'X-API-Key': apiKey,
      'Authorization': `Bearer ${apiKey}`,
    };
  }

  it('returns empty headers when no API key is provided', () => {
    expect(getAuthHeaders('')).toEqual({});
  });

  it('generates X-API-Key and Bearer Authorization headers when key is set', () => {
    const headers = getAuthHeaders('test-analyst-key-123');
    expect(headers['X-API-Key']).toBe('test-analyst-key-123');
    expect(headers['Authorization']).toBe('Bearer test-analyst-key-123');
  });
});
