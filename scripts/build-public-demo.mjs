import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { inspectPacket } from '../src/workflow.mjs';
import { renderMissionControl } from '../src/mission-control.mjs';

const fixture = fileURLToPath(new URL('../fixtures/trial.json', import.meta.url));
const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const expectedDigest = 'e4abc0efb00032e21ce6449654444fff7608ccae2b40baaef2dd56d3b5502f57';

try {
  if (process.argv.length !== 2) throw new Error('Unexpected arguments');
  const packet = execFileSync(process.execPath, [cli, 'build', fixture], { stdio: ['ignore', 'pipe', 'pipe'] });
  const report = inspectPacket(packet, expectedDigest);
  if (report.sentinel.status !== 'passed') throw new Error('Synthetic fixture digest changed');
  process.stdout.write(renderMissionControl(report));
} catch {
  process.stderr.write('Public demo build requires the reviewed synthetic fixture.\n');
  process.exitCode = 1;
}
