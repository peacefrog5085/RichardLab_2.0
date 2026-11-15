import { MAX_SOURCE, reviewEvidence, sha256, verify } from './sentinel.mjs';
import { analyzeClaims } from './echo.mjs';
import { reviewClaims } from './jester.mjs';

export { sha256 };

export function createPacket(sources, claims) {
  const records = sources.map(({ id, origin, revision, bytes, kind }) => {
    if (!Buffer.isBuffer(bytes) || bytes.length > MAX_SOURCE) throw new Error('Invalid source size');
    return { id, origin, revision, digest: sha256(bytes), data: bytes.toString('base64'), kind };
  });
  const packet = Buffer.from(JSON.stringify({ version: 1, sources: records, claims }));
  const check = verify(packet, sha256(packet));
  if (check.status !== 'passed') throw new Error('Packet schema or evidence validation failed');
  return packet;
}

export function inspectPacket(bytes, pin) {
  const { status, findings, sources, claims } = verify(bytes, pin);
  const sentinel = { status, findings };
  if (status === 'blocked') return { version: 1, sentinel };
  const echo = analyzeClaims(claims, sources);
  return {
    version: 1,
    packetDigest: pin,
    sentinel: { ...sentinel, advisories: reviewEvidence(sources) },
    evidence: [...sources.values()].map(({ id, digest }) => ({ id, digest })),
    echo,
    jester: reviewClaims(echo, sources),
  };
}

export function inspectProvenance(bytes, pin) {
  const { status, findings, sources } = verify(bytes, pin);
  const report = { version: 1, sentinel: { status, findings } };
  if (status === 'blocked') return report;
  return {
    ...report,
    packetDigest: pin,
    evidence: [...sources.values()].map(({ id, origin, revision, digest, text }) => ({
      id, declaredOrigin: origin, declaredRevision: revision, digest, bytes: Buffer.byteLength(text),
    })),
  };
}
