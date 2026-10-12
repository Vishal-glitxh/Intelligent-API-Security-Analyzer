/**
 * Redacts potential credentials, JWT tokens, Bearer tokens, and secrets from text.
 */
export function redactSecrets(text: string): string {
  if (!text) return text;

  let result = text;

  // Redact Bearer tokens (any non-whitespace sequence after Bearer)
  result = result.replace(/Bearer\s+[^\s"'\n]+/gi, 'Bearer [REDACTED]');

  // Redact raw JWT tokens
  result = result.replace(/eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g, '[REDACTED_JWT]');

  // Redact key/secret/password/token parameter assignments (in JSON or key=value formats)
  result = result.replace(
    /(["']?(?:api[_-]?key|secret|password|access[_-]?token|auth[_-]?token|token)["']?\s*[:=]\s*)(['"][^'"]+['"]|[^\s,}\]]+)/gi,
    '$1"[REDACTED]"'
  );

  return result;
}
