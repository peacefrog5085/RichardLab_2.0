import { open, lstat, realpath } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { MAX_PACKET, MAX_SOURCE, digestPattern } from './sentinel.mjs';
import { createPacket, inspectPacket, inspectProvenance } from './workflow.mjs';
import { renderMissionControl } from './mission-control.mjs';
import { reviewWebSnapshot } from './web-review.mjs';

async function readBounded(path, max) {
  const entry = await lstat(path);
  if (!entry.isFile() || entry.size > max) throw new Error('Unsupported input file');
  const handle = await open(path, 'r');
  try {
    if (!(await handle.stat()).isFile()) throw new Error('Unsupported input file');
    const chunks = [];
    let size = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      size += chunk.length;
      if (size > max) throw new Error('Input exceeds size limit');
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  } finally {
    await handle.close();
  }
}

async function build(specPath) {
  const spec = JSON.parse(new TextDecoder('utf-8', { fatal: true })
    .decode(await readBounded(specPath, 128 * 1024)));
  if (!Array.isArray(spec.sources) || spec.sources.length < 1 || spec.sources.length > 16) {
    throw new Error('Invalid source list');
  }
  const root = await realpath(dirname(resolve(specPath)));
  const sources = [];
  for (const { file, id, origin, revision, kind } of spec.sources) {
    const extension = kind === undefined ? 'txt' : 'json';
    if (typeof file !== 'string'
        || !new RegExp('^[a-z0-9][a-z0-9_-]{0,63}\\.' + extension + '$', 'i').test(file)
        || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])\./i.test(file)) {
      throw new Error('Use a plain adjacent evidence filename');
    }
    sources.push({ id, origin, revision, kind, bytes: await readBounded(join(root, file), MAX_SOURCE) });
  }
  process.stdout.write(createPacket(sources, spec.claims));
}

async function inspectCases(indexPath) {
  const cases = JSON.parse(new TextDecoder('utf-8', { fatal: true })
    .decode(await readBounded(indexPath, 32 * 1024)));
  if (!Array.isArray(cases) || cases.length < 1 || cases.length > 32) {
    throw new Error('Invalid case list');
  }
  const ids = new Set();
  for (const { id, file, sha256 } of cases) {
    if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(id) || ids.has(id)
        || typeof file !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}\.packet\.json$/i.test(file)
        || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])\./i.test(file)
        || typeof sha256 !== 'string' || sha256.length !== 64 || !digestPattern.test(sha256)) {
      throw new Error('Invalid case entry');
    }
    ids.add(id);
  }
  const root = await realpath(dirname(resolve(indexPath)));
  const reports = [];
  for (const { id, file, sha256 } of cases) {
    let bytes;
    try {
      bytes = await readBounded(join(root, file), MAX_PACKET);
    } catch {
      reports.push({ id, sentinel: { status: 'blocked', findings: ['packet-unreadable'] } });
      continue;
    }
    reports.push({ id, ...inspectPacket(bytes, sha256) });
  }
  return reports;
}

try {
  const [command, file, digest, ...extra] = process.argv.slice(2);
  if (command === 'build' && file && !digest && !extra.length) {
    await build(file);
  } else if (command === 'web-review' && file && !digest && !extra.length) {
    const report = reviewWebSnapshot(await readBounded(file, 64 * 1024));
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else if (command === 'cases' && file && !digest && !extra.length) {
    const reports = await inspectCases(file);
    process.stdout.write(renderMissionControl(reports));
    if (reports.some(report => report.sentinel.status === 'blocked')) process.exitCode = 1;
  } else if (['inspect', 'dashboard', 'provenance'].includes(command) && file && digest?.length === 64
      && digestPattern.test(digest) && !extra.length) {
    const bytes = await readBounded(file, MAX_PACKET);
    const report = command === 'provenance' ? inspectProvenance(bytes, digest) : inspectPacket(bytes, digest);
    process.stdout.write(command === 'dashboard'
      ? renderMissionControl(report)
      : JSON.stringify(report, null, 2) + '\n');
    if (report.sentinel.status === 'blocked') process.exitCode = 1;
  } else {
    process.stderr.write('Usage: node src/cli.mjs build SPEC | {inspect|dashboard|provenance} PACKET SHA256 | cases INDEX | web-review SNAPSHOT\n');
    process.exitCode = 2;
  }
} catch {
  process.stderr.write('RichardLab could not read or validate the input. Check the documented format and limits.\n');
  process.exitCode = 2;
}
