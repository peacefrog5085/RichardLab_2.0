import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../scripts/build-public-demo.mjs', import.meta.url));
const build = (...args) => spawnSync(process.execPath, [script, ...args]);

test('builds a reproducible public dashboard with no source text or active content', () => {
  const first = build();
  assert.equal(first.status, 0, first.stderr.toString());
  assert.deepEqual(first.stdout, build().stdout);
  const html = first.stdout.toString();
  assert.match(html, /Sentinel passed integrity checks/);
  assert.match(html, /single-declared-origin/);
  assert.doesNotMatch(html, /The synthetic trial|trial\.txt|<script|<iframe|\b(?:src|href)=/i);
});

test('public dashboard command rejects alternate inputs', () => {
  const result = build('some-case.packet.json');
  assert.equal(result.status, 1);
  assert.equal(result.stdout.length, 0);
  assert.doesNotMatch(result.stderr.toString(), /some-case/);
});

test('public dashboard command refuses a modified synthetic fixture', t => {
  const dir = mkdtempSync(join(tmpdir(), 'richardlab-public-demo-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const folder of ['scripts', 'src', 'fixtures']) {
    cpSync(fileURLToPath(new URL('../' + folder + '/', import.meta.url)), join(dir, folder),
      { recursive: true });
  }
  writeFileSync(join(dir, 'fixtures', 'trial.txt'), 'Locally changed evidence\n');
  const result = spawnSync(process.execPath, [join(dir, 'scripts', 'build-public-demo.mjs')]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.length, 0);
  assert.match(result.stderr.toString(), /reviewed synthetic fixture/);
  assert.doesNotMatch(result.stderr.toString(), /Locally changed evidence/);
});
