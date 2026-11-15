import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { reviewWebSnapshot } from '../src/web-review.mjs';
import { createPacket, inspectPacket, sha256 } from '../src/workflow.mjs';

const review = (url, headers = {}) => reviewWebSnapshot(Buffer.from(JSON.stringify({ url, headers })));

test('web review separates missing policies from header presence', () => {
  const url = 'https://sample.example.invalid/';
  assert.deepEqual(review(url, {
    'Content-Type': 'Text/HTML; charset=UTF-8',
    'Content-Security-Policy-Report-Only': "default-src 'none'",
  }).findings, ['hsts-header-missing', 'html-csp-header-missing']);
  assert.deepEqual(review(url, {
    'Content-Type': 'text/html', 'content-security-policy': "default-src 'none'",
    'Strict-Transport-Security': 'max-age=86400',
  }).findings, []);
  assert.deepEqual(review(url, { 'Content-Type': 'application/json' }).findings, ['hsts-header-missing']);
});

test('web review does not disclose snapshot URL or header values', () => {
  const report = review('http://name:secret@example.invalid/private', { 'Set-Cookie': 'session=private' });
  assert.deepEqual(report.findings, ['cleartext-response-url', 'url-with-user-info']);
  assert.doesNotMatch(JSON.stringify(report), /example\.invalid|secret|private|session/);
});

test('web review rejects ambiguity and non-web URLs', () => {
  assert.throws(() => review('file:///sample'), /scheme/);
  assert.throws(() => review('https://sample.example.invalid', { Foo: '1', foo: '2' }), /header/);
  assert.throws(() => review('https://sample.example.invalid', { Foo: 'a\nb' }), /header/);
});

test('CLI reviews the synthetic response fixture', () => {
  const cwd = fileURLToPath(new URL('../', import.meta.url));
  const result = spawnSync(process.execPath, ['src/cli.mjs', 'web-review', 'fixtures/web-response.json'], { cwd });
  assert.equal(result.status, 0, result.stderr.toString());
  assert.deepEqual(JSON.parse(result.stdout).findings, ['hsts-header-missing', 'html-csp-header-missing']);
});

test('a malformed typed snapshot becomes an advisory after packet integrity passes', () => {
  const input = { id: 'snapshot', origin: 'log', revision: 'v1', bytes: Buffer.from('no JSON') };
  const claims = [{ id: 'test', text: 'Synthetic trial', citations: [] }];
  const packet = createPacket([{ ...input, kind: 'web-response' }], claims);
  const result = inspectPacket(packet, sha256(packet));
  assert.equal(result.sentinel.status, 'passed');
  assert.deepEqual(result.sentinel.advisories, [
    { source: 'snapshot', code: 'invalid-web-response-snapshot' },
  ]);
  assert.throws(() => createPacket([{ ...input, kind: 'unknown' }], claims), /schema/);
});
