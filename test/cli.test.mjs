import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '../src/workflow.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const run = (...args) => spawnSync(process.execPath, ['src/cli.mjs', ...args], { cwd: root });

test('CLI produces a reproducible report and rejects a changed packet', t => {
  const dir = mkdtempSync(join(tmpdir(), 'richardlab-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'case.packet.json');
  const build = () => execFileSync(process.execPath, ['src/cli.mjs', 'build', 'fixtures/trial.json'],
    { cwd: root });
  const bytes = build();
  assert.deepEqual(bytes, build());
  assert.ok(!bytes.includes(Buffer.from('trial.txt')));
  writeFileSync(file, bytes);
  const pin = sha256(bytes);
  const result = run('inspect', file, pin);
  assert.equal(result.status, 0);
  assert.deepEqual(result.stdout, run('inspect', file, pin).stdout);
  assert.equal(JSON.parse(result.stdout).sentinel.status, 'passed');
  assert.ok(!result.stdout.toString().includes('The trial'));
  const provenance = run('provenance', file, pin);
  assert.equal(provenance.status, 0);
  const records = JSON.parse(provenance.stdout);
  assert.deepEqual(records.evidence, [{
    id: 'log', declaredOrigin: 'trial-log', declaredRevision: 'v1',
    digest: JSON.parse(bytes).sources[0].digest, bytes: 35,
  }]);
  assert.doesNotMatch(provenance.stdout.toString(), /The trial|trial\.txt|citations/);
  const dashboard = run('dashboard', file, pin);
  assert.equal(dashboard.status, 0);
  assert.match(dashboard.stdout.toString(), /Sentinel passed integrity checks/);
  assert.ok(!dashboard.stdout.toString().includes('The trial'));
  writeFileSync(file, Buffer.concat([bytes, Buffer.from(' ')]));
  const blocked = run('inspect', file, pin);
  assert.equal(blocked.status, 1);
  assert.deepEqual(JSON.parse(blocked.stdout).sentinel.findings, ['packet-digest-mismatch']);
  const blockedProvenance = run('provenance', file, pin);
  assert.equal(blockedProvenance.status, 1);
  assert.deepEqual(JSON.parse(blockedProvenance.stdout), JSON.parse(blocked.stdout));
  const blockedDashboard = run('dashboard', file, pin);
  assert.equal(blockedDashboard.status, 1);
  assert.match(blockedDashboard.stdout.toString(), /Sentinel blocked inspection/);
  assert.doesNotMatch(blockedDashboard.stdout.toString(), /<table/);
});

test('CLI refuses evidence paths outside the spec directory', t => {
  const dir = mkdtempSync(join(tmpdir(), 'richardlab-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'spec.json');
  writeFileSync(file, JSON.stringify({ sources: [{ file: '../outside.txt' }] }));
  const result = run('build', file);
  assert.equal(result.status, 2);
  assert.equal(result.stdout.length, 0);
  assert.ok(!result.stderr.toString().includes(dir));
});

test('case dashboard isolates valid, altered and missing packets', t => {
  const dir = mkdtempSync(join(tmpdir(), 'richardlab-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bytes = execFileSync(process.execPath, ['src/cli.mjs', 'build', 'fixtures/trial.json'],
    { cwd: root });
  writeFileSync(join(dir, 'first.packet.json'), bytes);
  writeFileSync(join(dir, 'changed.packet.json'), Buffer.concat([bytes, Buffer.from(' ')]));
  const index = join(dir, 'cases.json');
  const cases = ['first', 'changed', 'missing'].map(id => ({
    id, file: id + '.packet.json', sha256: sha256(bytes),
  }));
  writeFileSync(index, JSON.stringify(cases));
  const result = run('cases', index);
  assert.equal(result.status, 1);
  assert.match(result.stdout.toString(), /3 cases · 2 blocked/);
  assert.match(result.stdout.toString(), /Sentinel passed integrity checks/);
  assert.match(result.stdout.toString(), /packet-digest-mismatch/);
  assert.match(result.stdout.toString(), /packet-unreadable/);
  assert.doesNotMatch(result.stdout.toString(), /\.packet\.json|The trial/);
  writeFileSync(index, JSON.stringify([cases[0], cases[0]]));
  assert.equal(run('cases', index).status, 2);
});

test('typed web evidence reaches Mission Control through the CLI', t => {
  const dir = mkdtempSync(join(tmpdir(), 'richardlab-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const built = run('build', 'fixtures/web-investigation.json');
  assert.equal(built.status, 0, built.stderr.toString());
  const packet = join(dir, 'web.packet.json');
  writeFileSync(packet, built.stdout);
  const pin = sha256(built.stdout);
  const output = run('inspect', packet, pin);
  assert.equal(output.status, 0);
  const report = JSON.parse(output.stdout);
  assert.deepEqual(report.sentinel.advisories, [
    { source: 'response', code: 'hsts-header-missing' },
    { source: 'response', code: 'html-csp-header-missing' },
  ]);
  assert.equal(report.echo[0].citations[0].status, 'matched');
  const dashboard = run('dashboard', packet, pin);
  assert.equal(dashboard.status, 0);
  assert.match(dashboard.stdout.toString(), /html-csp-header-missing/);
  assert.doesNotMatch(dashboard.stdout.toString(), /example\.invalid|charset=utf-8/);
});
