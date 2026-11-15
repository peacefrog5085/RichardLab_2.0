import { sha256 } from './digest.mjs';
import { reviewWebSnapshot } from './web-review.mjs';
import { reviewAiControls } from './ai-review.mjs';

const snapshotReviews = new Map([
  ['web-response', reviewWebSnapshot],
  ['ai-controls', reviewAiControls],
]);

export const MAX_SOURCE = 128 * 1024;
export const MAX_PACKET = 4 * 1024 * 1024;
export const digestPattern = /^[a-f0-9]{64}$/;
const identifier = value => typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value);
const text = (value, max) => typeof value === 'string' && value.length <= max && !!value.trim();
const collection = (value, max) => Array.isArray(value) && value.length > 0 && value.length <= max;
const fields = (value, ...keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
export { sha256 };

export function reviewEvidence(sources) {
  const advisories = [];
  for (const { id, text, kind } of sources.values()) {
    const codes = new Set();
    if (/\b(?:ignore|override|disregard)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|rules)\b/i.test(text)) {
      codes.add('possible-instruction-override');
    }
    for (const [candidate] of text.matchAll(/\bhttps?:\/\/[^\s<>"']+/gi)) {
      if (candidate.length > 2048 || !URL.canParse(candidate)) continue;
      const url = new URL(candidate);
      if (url.protocol === 'http:') codes.add('cleartext-http-link');
      if (url.username || url.password) codes.add('url-with-user-info');
    }
    const reviewSnapshot = snapshotReviews.get(kind);
    if (reviewSnapshot) {
      try {
        for (const finding of reviewSnapshot(Buffer.from(text)).findings) codes.add(finding);
      } catch {
        codes.add('invalid-' + kind + '-snapshot');
      }
    }
    for (const code of codes) advisories.push({ source: id, code });
  }
  return advisories;
}

function validPacket(packet) {
  if (!fields(packet, 'version', 'sources', 'claims') || packet.version !== 1
      || !collection(packet.sources, 16) || !collection(packet.claims, 64)) return false;
  const ids = new Set();
  for (const source of packet.sources) {
    if (!(fields(source, 'id', 'origin', 'revision', 'digest', 'data')
          || (fields(source, 'id', 'origin', 'revision', 'digest', 'data', 'kind')
            && snapshotReviews.has(source.kind)))
        || !identifier(source.id) || ids.has(source.id) || !identifier(source.origin)
        || !text(source.revision, 128) || typeof source.digest !== 'string'
        || !digestPattern.test(source.digest) || typeof source.data !== 'string'
        || source.data.length > Math.ceil(MAX_SOURCE / 3) * 4) return false;
    ids.add(source.id);
  }
  const claimIds = new Set();
  for (const claim of packet.claims) {
    if (!fields(claim, 'id', 'text', 'citations') || !identifier(claim.id)
        || claimIds.has(claim.id) || !text(claim.text, 2048)
        || !Array.isArray(claim.citations) || claim.citations.length > 8
        || !claim.citations.every(citation => (fields(citation, 'source', 'quote')
          || (fields(citation, 'source', 'quote', 'stance')
            && ['supports', 'challenges', 'context'].includes(citation.stance)))
          && ids.has(citation.source) && text(citation.quote, 1024))) return false;
    claimIds.add(claim.id);
  }
  return true;
}

export function verify(bytes, pin) {
  const block = finding => ({ status: 'blocked', findings: [finding] });
  if (typeof pin !== 'string' || !digestPattern.test(pin)) return block('invalid-expected-digest');
  if (bytes.length > MAX_PACKET) return block('packet-too-large');
  if (sha256(bytes) !== pin) return block('packet-digest-mismatch');
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let packet;
  try {
    packet = JSON.parse(decoder.decode(bytes));
  } catch {
    return block('invalid-json');
  }
  if (!validPacket(packet)) return block('invalid-packet');
  const sources = new Map();
  for (const { data, id, digest, origin, revision, kind } of packet.sources) {
    const source = Buffer.from(data, 'base64');
    if (source.length === 0 || source.length > MAX_SOURCE || source.toString('base64') !== data) {
      return block('invalid-source-encoding:' + id);
    }
    if (sha256(source) !== digest) return block('source-digest-mismatch:' + id);
    try {
      sources.set(id, { id, origin, revision, digest, kind, text: decoder.decode(source) });
    } catch {
      return block('invalid-source-text:' + id);
    }
  }
  return { status: 'passed', findings: [], sources, claims: packet.claims };
}
