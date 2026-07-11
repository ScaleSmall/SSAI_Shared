import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' });
}

const dirty = git(['status', '--short', '--untracked-files=all'])
  .split(/\r?\n/)
  .map((line) => line.trimEnd())
  .filter(Boolean);

if (dirty.length) {
  console.error('[hygiene] Repo has tracked or untracked source changes:');
  for (const line of dirty) console.error(`  ${line}`);
  console.error('[hygiene] Implement real source changes or remove accidental files before release.');
  process.exit(1);
}

const ignored = git(['status', '--short', '--ignored=matching', '--untracked-files=normal'])
  .split(/\r?\n/)
  .map((line) => line.trimEnd())
  .filter((line) => line.startsWith('!! '));

const topLevelCounts = new Map();
for (const line of ignored) {
  const rel = line.slice(3).replace(/\\/g, '/');
  const top = rel.split('/')[0] || rel;
  topLevelCounts.set(top, (topLevelCounts.get(top) ?? 0) + 1);
}

const summary = [...topLevelCounts.entries()]
  .sort(([left], [right]) => left.localeCompare(right))
  .map(([name, count]) => `${name}:${count}`)
  .join(', ');

console.log('[hygiene] SSAI_Shared source tree clean');
console.log(`[hygiene] Ignored local artifacts are not release source${summary ? ` (${summary})` : ''}`);
