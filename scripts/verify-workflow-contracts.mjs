import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

const readWorkflow = async (name) =>
  (await readFile(path.join(repoRoot, '.github', 'workflows', name), 'utf8')).replace(/\r\n/g, '\n');

const requireText = (source, expected, description) => {
  if (!source.includes(expected)) {
    throw new Error(`Missing ${description}: ${expected}`);
  }
};

const rejectPattern = (source, pattern, description) => {
  if (pattern.test(source)) {
    throw new Error(`Workflow contract violation: ${description}`);
  }
};

const validate = await readWorkflow('validate.yml');
const propagate = await readWorkflow('propagate.yml');
const releaseHealth = await readWorkflow('release-health-monitor.yml');
const releaseHealthVerifier = await readFile(path.join(repoRoot, 'scripts', 'verify-org-release-health.mjs'), 'utf8');
const combined = `${validate}\n${propagate}\n${releaseHealth}`;

requireText(validate, 'permissions:\n  contents: read', 'read-only workflow permissions');
requireText(validate, 'runs-on: ubuntu-24.04', 'pinned validation runner');
requireText(validate, 'persist-credentials: false', 'checkout credential isolation');
requireText(validate, "node-version: '24'", 'current Node runtime');
requireText(validate, 'run: npm run check', 'full shared package check');

requireText(propagate, 'workflow_dispatch:', 'manual propagation control');
requireText(propagate, 'dispatch_connect:', 'protected Connect dispatch gate');
requireText(propagate, 'permissions:\n  contents: read', 'read-only propagation permissions');
requireText(propagate, 'runs-on: ubuntu-24.04', 'pinned propagation runner');
requireText(propagate, 'SSAI_Connect dispatch is intentionally skipped', 'protected Connect skip');
requireText(propagate, "repos/ScaleSmall/SSAI_Connect/dispatches", 'manual Connect dispatch target');
requireText(propagate, "github.event_name == 'workflow_dispatch' && inputs.dispatch_connect == 'true'", 'manual Connect dispatch guard');
requireText(propagate, "repos/ScaleSmall/SSAI_Dashboard/dispatches", 'Dashboard dispatch target');
requireText(propagate, 'GH_TOKEN: ${{ secrets.SCALESMALL_PAT }}', 'repository dispatch token source');

requireText(releaseHealth, 'workflow_dispatch:', 'manual release-health control');
requireText(releaseHealth, "cron: '*/15 * * * *'", '15-minute release-health schedule');
requireText(releaseHealth, 'permissions:\n  contents: read', 'read-only release-health permissions');
requireText(releaseHealth, 'cancel-in-progress: false', 'non-cancelling release-health serialization');
requireText(releaseHealth, 'runs-on: ubuntu-24.04', 'pinned release-health runner');
requireText(releaseHealth, 'persist-credentials: false', 'release-health checkout credential isolation');
requireText(releaseHealth, "node-version: '24'", 'release-health Node runtime');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_GITHUB_TOKEN: ${{ secrets.SCALESMALL_PAT }}', 'release-health organization token source');
requireText(releaseHealth, 'node scripts/verify-org-release-health.mjs', 'organization release-health verifier');
requireText(releaseHealthVerifier, 'latestByIdentity(', 'latest current-check selection');
requireText(releaseHealthVerifier, "check.app?.slug || check.app?.id || 'unknown-app'", 'provider-scoped check identity');

rejectPattern(combined, /ubuntu-latest/, 'floating GitHub runner label');
rejectPattern(combined, /peter-evans\/repository-dispatch@v\d+/i, 'floating repository-dispatch action');
rejectPattern(combined, /^\s*uses:\s+[^@\s]+\/[^@\s]+@v\d+\s*$/im, 'unpinned version-tag action');

console.log('Shared workflow hardening contract verified.');
