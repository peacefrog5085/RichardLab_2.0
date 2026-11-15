import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { inspectPacket, sha256 } from '../src/workflow.mjs';
import { renderMissionControl } from '../src/mission-control.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require(process.argv[2]);
const run = (...args) => execFileSync(process.execPath, args);
const build = name => run('src/cli.mjs', 'build', 'fixtures/' + name + '.json');
const verify = packet => inspectPacket(packet, sha256(packet));
const trial = build('trial');
const blocked = inspectPacket(Buffer.concat([trial, Buffer.from(' ')]), sha256(trial));
const pages = new Map([
  ['/', run('scripts/build-public-demo.mjs').toString('utf8')],
  ['/blocked', renderMissionControl(blocked)],
  ['/cases', renderMissionControl([
    { id: 'web', ...verify(build('web-investigation')) },
    { id: 'ai', ...verify(build('ai-investigation')) },
    { id: 'changed', ...blocked },
  ])],
]);

const browser = await chromium.launch();
try {
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 },
    { width: 320, height: 640 }]) {
    const mobile = viewport.width < 600;
    const context = await browser.newContext({ viewport, isMobile: mobile, hasTouch: mobile });
    const page = await context.newPage();
    const unexpected = [];
    page.on('pageerror', error => unexpected.push(error.message));
    page.on('console', message => {
      if (['error', 'warning'].includes(message.type())) unexpected.push(message.text());
    });
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      const html = url.origin === 'http://mission-control.invalid' && pages.get(url.pathname);
      if (!html) {
        unexpected.push('Unexpected request');
        return route.abort();
      }
      return route.fulfill({ contentType: 'text/html; charset=utf-8', body: html });
    });
    for (const [path, expected] of [
      ['/', ['Sentinel passed integrity checks', 'Evidence', 'Claim review', 'single-declared-origin']],
      ['/blocked', ['Sentinel blocked inspection', 'packet-digest-mismatch']],
      ['/cases', ['3 cases · 1 blocked', 'html-csp-header-missing',
        'external-writes-without-human-approval', 'packet-digest-mismatch']],
    ]) {
      const response = await page.goto('http://mission-control.invalid' + path);
      assert.equal(response.status(), 200);
      assert.equal(await page.getByRole('heading', { level: 1 }).innerText(), 'Mission Control');
      for (const label of expected) assert.ok(await page.getByText(label, { exact: true }).first().isVisible(), label);
      const layout = await page.evaluate(() => ({
        viewport: window.innerWidth,
        document: document.documentElement.scrollWidth,
        scrollers: [...document.querySelectorAll('.scroll')].map(element => [
          element.clientWidth, element.scrollWidth, getComputedStyle(element).overflowX,
        ]),
      }));
      assert.equal(layout.viewport, viewport.width);
      assert.ok(layout.document <= viewport.width + 1, 'Page overflows horizontally: ' + JSON.stringify(layout));
      assert.ok(layout.scrollers.every(([width, scroll, overflow]) => scroll <= width || overflow === 'auto'));
      if (path === '/blocked') assert.equal(await page.getByRole('table').count(), 0);
      else assert.ok(await page.getByRole('columnheader').count() > 0);
      assert.doesNotMatch(await page.locator('body').innerText(), /example\.invalid|charset=utf-8|permitsExternalWrites/);
      assert.deepEqual(unexpected, []);
      console.log(`PASS ${viewport.width}×${viewport.height} ${path}`);
    }
    await context.close();
  }
} finally {
  await browser.close();
}
