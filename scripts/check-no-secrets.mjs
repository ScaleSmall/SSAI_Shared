import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const allowedFiles = new Set(['package-lock.json']);
const allowedPatterns = [
  /Authorization/g,
  /Bearer/g,
  /api[_-]?key/gi,
  /token/gi,
];

const suspiciousPatterns = [
  { name: 'JWT-like token', pattern: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g },
  { name: 'GitHub token', pattern: /gh[pousr]_[A-Za-z0-9_]{30,}/g },
  { name: 'AWS access key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'Private key block', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----/g },
  { name: 'Generic assigned secret', pattern: /\b(?:secret|password|token|api[_-]?key)\b\s*[:=]\s*['"][^'"]{16,}['"]/gi },
];

const files = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' })
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter(Boolean)
  .filter((file) => !allowedFiles.has(file.replace(/\\/g, '/')));

const failures = [];

for (const file of files) {
  const rel = file.replace(/\\/g, '/');
  if (/\.(?:png|jpg|jpeg|gif|webp|ico|pdf|docx)$/i.test(rel)) continue;

  const fullPath = path.join(ROOT, rel);
  let text;
  try {
    text = readFileSync(fullPath, 'utf8');
  } catch {
    continue;
  }

  let scrubbed = text;
  for (const allowed of allowedPatterns) {
    scrubbed = scrubbed.replace(allowed, '');
  }

  for (const { name, pattern } of suspiciousPatterns) {
    pattern.lastIndex = 0;
    const matches = scrubbed.match(pattern);
    if (matches?.length) failures.push(`${rel}: ${name} (${matches.length})`);
  }
}

if (failures.length) {
  console.error('[secrets] Potential committed secrets found:');
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log('[secrets] SSAI_Shared OK');
