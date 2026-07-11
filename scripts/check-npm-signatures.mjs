import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
const shippedPackages = Object.entries(lock.packages || {})
  .filter(([name, meta]) => name && name.startsWith('node_modules/') && meta?.peer !== true);

if (shippedPackages.length === 0) {
  console.log('[signatures] SSAI_Shared has no shipped third-party npm packages to audit');
  process.exit(0);
}

execFileSync('npm', ['audit', 'signatures'], { stdio: 'inherit' });
