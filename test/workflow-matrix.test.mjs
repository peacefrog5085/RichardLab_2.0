import test from 'node:test';
import assert from 'node:assert/strict';
import { createPacket, inspectPacket, sha256 } from '../src/workflow.mjs';

const excerpts = {
  ascii: 'trial complete',
  accented: 'essai terminé',
  decomposed: 'essai termine\u0301',
  cjk: '試験完了',
  rtl: 'اكتملت التجربة',
  emoji: 'trial 🧪 complete',
};

const citationCases = {
  unique: { suffix: '', status: 'matched' },
  repeated: { suffix: ' repeat', status: 'ambiguous' },
  missing: { suffix: '', status: 'missing' },
  omitted: { suffix: '', status: undefined },
  multiline: { suffix: '\r\nnext line', status: 'matched' },
};

const sourceCases = {
  single: { origins: ['log'], copies: false, count: 1 },
  copied: { origins: ['log', 'log'], copies: true, count: 1 },
  distinctCopies: { origins: ['log', 'brief'], copies: true, count: 2 },
  sharedOrigin: { origins: ['log', 'log'], copies: false, count: 1 },
  independentLabels: { origins: ['log', 'brief', 'minutes'], copies: false, count: 3 },
};

for (const [language, excerpt] of Object.entries(excerpts)) {
  for (const [scenario, { suffix, status }] of Object.entries(citationCases)) {
    const quote = scenario === 'missing' ? excerpt + ' absent' : excerpt + (scenario === 'multiline' ? suffix : '');
    for (const [relationship, { origins, copies, count }] of Object.entries(sourceCases)) {
      const sources = origins.map((origin, index) => ({
        id: 'source-' + index, origin, revision: 'v1',
        bytes: Buffer.from((copies ? '📄 0: ' : '📄 ' + index + ': ')
          + excerpt + suffix + (scenario === 'repeated' ? ' ' + excerpt : '')),
      }));
      const citations = status ? sources.map(({ id }) => ({ source: id, quote })) : [];
      const packet = createPacket(sources, [{ id: 'finding', text: 'Synthetic claim', citations }]);
      const pin = sha256(packet);
      const name = [language, scenario, relationship].join(' / ');
      test('review / ' + name, () => {
        const report = inspectPacket(packet, pin);
        const matched = status === 'matched';
        assert.equal(report.sentinel.status, 'passed');
        assert.deepEqual(report.evidence.map(item => item.digest), sources.map(item => sha256(item.bytes)));
        assert.deepEqual(report.echo[0].citations.map(item => item.status), citations.map(() => status));
        if (matched) {
          const offset = Buffer.byteLength('📄 0: ');
          assert.deepEqual(report.echo[0].citations.map(({ start, end }) => [start, end]),
            citations.map(() => [offset, offset + Buffer.byteLength(quote)]));
        }
        assert.equal(report.jester[0].declaredOrigins, matched ? count : 0);
        assert.equal(report.jester[0].flags.includes('identical-source-bytes'), matched && copies);
        assert.doesNotMatch(JSON.stringify(report), /Synthetic claim/);
      });
      test('tamper / ' + name, () => {
        const altered = JSON.parse(packet);
        const target = altered.sources.at(-1);
        const evidence = Buffer.from(target.data, 'base64');
        evidence[evidence.length - 1] ^= 1;
        target.data = evidence.toString('base64');
        const bytes = Buffer.from(JSON.stringify(altered));
        assert.deepEqual(inspectPacket(bytes, pin).sentinel.findings, ['packet-digest-mismatch']);
        const internal = inspectPacket(bytes, sha256(bytes));
        assert.deepEqual(internal.sentinel.findings, ['source-digest-mismatch:' + target.id]);
        assert.equal(internal.echo, undefined);
      });
    }
  }
}
