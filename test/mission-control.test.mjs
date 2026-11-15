import test from 'node:test';
import assert from 'node:assert/strict';
import { renderMissionControl } from '../src/mission-control.mjs';

test('renders a blocked Sentinel result without evidence tables', () => {
  const html = renderMissionControl({ sentinel: { status: 'blocked', findings: ['packet-digest-mismatch'] } });
  assert.match(html, /Sentinel blocked inspection/);
  assert.match(html, /packet-digest-mismatch/);
  assert.doesNotMatch(html, /<table/);
});

test('renders report values as inert text', () => {
  const payload = '<img src=https://example.invalid>';
  const html = renderMissionControl({
    sentinel: { status: 'passed', findings: [], advisories: [
      { source: 'log', code: 'cleartext-http-link' },
    ] }, packetDigest: 'abc',
    evidence: [{ id: payload, digest: 'def' }],
    echo: [{ id: 'claim', citations: [{ source: 'log', status: 'matched', start: 0, end: 12 }] }],
    jester: [{ id: 'claim', declaredOrigins: 1, flags: ['single-declared-origin'] }],
  });
  assert.match(html, /default-src 'none'/);
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes(payload));
  assert.match(html, /single-declared-origin/);
  assert.match(html, /cleartext-http-link/);
});
