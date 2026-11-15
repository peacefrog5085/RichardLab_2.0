import { sha256 } from './digest.mjs';

export function reviewWebSnapshot(bytes) {
  const snapshot = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!snapshot || typeof snapshot.url !== 'string' || snapshot.url.length > 2048
      || /[\u0000-\u0020\u007f]/.test(snapshot.url) || !URL.canParse(snapshot.url)
      || !snapshot.headers || typeof snapshot.headers !== 'object' || Array.isArray(snapshot.headers)) {
    throw new Error('Invalid web response snapshot');
  }
  const url = new URL(snapshot.url);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Unsupported response scheme');

  const headers = new Map();
  for (const [name, value] of Object.entries(snapshot.headers)) {
    const key = name.toLowerCase();
    if (!/^[!#$%&'*+.^_0-9a-z|~-]+$/.test(key) || headers.has(key)
        || typeof value !== 'string' || /[\r\n\u0000]/.test(value)) {
      throw new Error('Invalid response header');
    }
    headers.set(key, value.trim());
  }
  const findings = [];
  if (url.protocol === 'http:') findings.push('cleartext-response-url');
  if (url.username || url.password) findings.push('url-with-user-info');
  if (url.protocol === 'https:' && !headers.get('strict-transport-security')) {
    findings.push('hsts-header-missing');
  }
  const contentType = headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (['text/html', 'application/xhtml+xml'].includes(contentType)
      && !headers.get('content-security-policy')) findings.push('html-csp-header-missing');
  return { version: 1, snapshotDigest: sha256(bytes), findings };
}
