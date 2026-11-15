import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createPacket, inspectPacket, sha256 } from '../src/workflow.mjs';
import { renderMissionControl } from '../src/mission-control.mjs';

const cwd = fileURLToPath(new URL('../', import.meta.url));
const snapshot = JSON.parse(readFileSync(new URL('../fixtures/ai-controls.json', import.meta.url)));

test('AI control snapshots flow through CLI ingestion, Sentinel and Mission Control', () => {
  const result = spawnSync(process.execPath, ['src/cli.mjs', 'build', 'fixtures/ai-investigation.json'], { cwd });
  assert.equal(result.status, 0, result.stderr.toString());
  const report = inspectPacket(result.stdout, sha256(result.stdout));
  assert.equal(report.sentinel.status, 'passed');
  assert.deepEqual(report.sentinel.advisories.map(item => item.code), [
    'evidence-instruction-boundary-missing',
    'tool-access-unrestricted',
    'external-writes-without-human-approval',
    'raw-evidence-leaves-local-environment',
  ]);
  assert.equal(report.echo[0].citations[0].status, 'matched');
  const html = renderMissionControl(report);
  assert.match(html, /external-writes-without-human-approval/);
  assert.doesNotMatch(html, /requiresHumanApprovalForWrites|permitsExternalWrites/);
});

test('AI review distinguishes disabled writes and invalid snapshot metadata', () => {
  const safe = {
    treatsEvidenceAsUntrusted: true,
    restrictsToolAccess: true,
    permitsExternalWrites: false,
    requiresHumanApprovalForWrites: false,
    sendsRawEvidenceToProvider: false,
  };
  const scan = controls => {
    const bytes = createPacket([{
      id: 'controls', origin: 'test', revision: 'v1', kind: 'ai-controls',
      bytes: Buffer.from(JSON.stringify(controls)),
    }], [{ id: 'claim', text: 'Synthetic claim', citations: [] }]);
    return inspectPacket(bytes, sha256(bytes)).sentinel.advisories;
  };
  assert.deepEqual(scan(safe), []);
  assert.deepEqual(scan({ ...safe, permitsExternalWrites: true, requiresHumanApprovalForWrites: true }), []);
  assert.deepEqual(scan({ ...snapshot, restrictsToolAccess: 'unknown' }), [
    { source: 'controls', code: 'invalid-ai-controls-snapshot' },
  ]);
});
