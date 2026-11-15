import test from 'node:test';
import assert from 'node:assert/strict';
import { createPacket, inspectPacket, sha256 } from '../src/workflow.mjs';
import { renderMissionControl } from '../src/mission-control.mjs';

const sources = [
  { id: 'log', origin: 'trial-log', revision: 'v1', bytes: Buffer.from('Trial began at noon.') },
  { id: 'notes', origin: 'field-notes', revision: 'v1', bytes: Buffer.from('Trial began at dawn.') },
];
function review(quote, stance = 'challenges') {
  const bytes = createPacket(sources, [{
    id: 'timing', text: 'The trial began at noon.',
    citations: [
      { source: 'log', quote: 'at noon', stance: 'supports' },
      { source: 'notes', quote, stance },
    ],
  }]);
  return inspectPacket(bytes, sha256(bytes));
}
test('matched opposing declarations appear in Echo, Jester and Mission Control', () => {
  const report = review('at dawn');
  assert.deepEqual(report.echo[0].citations.map(item => item.declaredStance), ['supports', 'challenges']);
  assert.ok(report.jester[0].flags.includes('conflicting-declared-stances'));
  const html = renderMissionControl(report);
  assert.match(html, /declared challenges/);
  assert.doesNotMatch(html, /Trial began|at dawn/);
});
test('unmatched quotations cannot create a reported conflict', () => {
  const report = review('at dusk');
  assert.equal(report.echo[0].citations[1].status, 'missing');
  assert.equal(report.echo[0].citations[1].declaredStance, undefined);
  assert.ok(!report.jester[0].flags.includes('conflicting-declared-stances'));
});
test('Sentinel rejects an unrecognized declared stance', () => {
  assert.throws(() => review('at dawn', 'certified'), /schema/);
});
