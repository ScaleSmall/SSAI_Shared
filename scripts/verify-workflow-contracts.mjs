import { readFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const workflowDirectory = path.join(repoRoot, '.github', 'workflows');

const readWorkflow = async (name) =>
  (await readFile(path.join(workflowDirectory, name), 'utf8')).replace(/\r\n?|\n/g, '\n');

const readSource = async (...segments) =>
  (await readFile(path.join(repoRoot, ...segments), 'utf8')).replace(/\r\n?|\n/g, '\n');

const requireText = (source, expected, description) => {
  if (!source.includes(expected)) {
    throw new Error(`Missing ${description}: ${expected}`);
  }
};

const assertRecoveryPolicyFields = (block, key, expectedFields) => {
  for (const [expected, description] of expectedFields) {
    requireText(block, expected, `${key} ${description}`);
  }
};

const requireRecoveryPolicyBlock = (source, key, expectedFields) => {
  const marker = `['${key}', {`;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`Missing recovery policy: ${key}`);
  const end = source.indexOf('\n  }],', start);
  if (end < 0) throw new Error(`Unterminated recovery policy: ${key}`);
  const block = source.slice(start, end + '\n  }],'.length);
  assertRecoveryPolicyFields(block, key, expectedFields);
  return block;
};

const rejectPattern = (source, pattern, description) => {
  if (pattern.test(source)) {
    throw new Error(`Workflow contract violation: ${description}`);
  }
};

const collectWorkflowSources = async () => {
  const entries = await readdir(workflowDirectory, { withFileTypes: true });
  const workflowEntries = entries
    .filter((entry) => /\.ya?ml$/i.test(entry.name))
    .sort((left, right) => left.name.localeCompare(right.name));
  if (workflowEntries.length === 0) throw new Error('No GitHub workflow sources were found.');

  const sources = new Map();
  for (const entry of workflowEntries) {
    if (!entry.isFile()) {
      throw new Error(`GitHub workflow source is not a regular file: ${entry.name}`);
    }
    const canonicalName = entry.name.toLowerCase();
    if ([...sources.keys()].some((name) => name.toLowerCase() === canonicalName)) {
      throw new Error(`Duplicate case-insensitive GitHub workflow source: ${entry.name}`);
    }
    sources.set(entry.name, await readWorkflow(entry.name));
  }
  return sources;
};

const requireWorkflowSource = (sources, name) => {
  const source = sources.get(name);
  if (typeof source !== 'string') throw new Error(`Missing required GitHub workflow source: ${name}`);
  return source;
};

const assertNoLegacyCrossRepositoryPat = (sources) => {
  if (!(sources instanceof Map) || sources.size === 0) {
    throw new TypeError('workflow sources must be a non-empty Map');
  }
  for (const [name, source] of sources) {
    if (typeof name !== 'string' || !/^[A-Za-z0-9._-]+\.ya?ml$/i.test(name) || typeof source !== 'string') {
      throw new TypeError('workflow source inventory contains an invalid entry');
    }
    if (/\bSCALESMALL_PAT\b/.test(source)) {
      throw new Error(`Workflow contract violation: ${name} references the retired SCALESMALL_PAT identifier`);
    }
  }
};

const requireBalancedExpressions = (source, description) => {
  const openings = source.match(/\$\{\{/g)?.length ?? 0;
  const closings = source.match(/\}\}/g)?.length ?? 0;
  if (openings !== closings) throw new Error(`Unbalanced GitHub expressions in ${description}: ${openings}/${closings}`);
};

const requireSpaceIndentation = (source, description) => {
  const tabbedLine = source.split('\n').findIndex((line) => /^\s*\t|\t/.test(line));
  if (tabbedLine >= 0) throw new Error(`${description} contains a tab on line ${tabbedLine + 1}`);
};

const expandCronMinuteField = (field, description) => {
  const minutes = new Set();
  for (const segment of field.split(',')) {
    const [range, rawStep] = segment.split('/');
    const step = rawStep === undefined ? 1 : Number.parseInt(rawStep, 10);
    const [rawStart, rawEnd] = range === '*'
      ? ['0', '59']
      : range.includes('-')
        ? range.split('-')
        : [range, range];
    const start = Number.parseInt(rawStart, 10);
    const end = Number.parseInt(rawEnd, 10);
    if (
      !Number.isInteger(start)
      || !Number.isInteger(end)
      || !Number.isInteger(step)
      || start < 0
      || end > 59
      || start > end
      || step < 1
    ) {
      throw new Error(`Invalid cron minute field for ${description}: ${field}`);
    }
    for (let minute = start; minute <= end; minute += step) minutes.add(minute);
  }
  return minutes;
};

const workflowSources = await collectWorkflowSources();
const validate = requireWorkflowSource(workflowSources, 'validate.yml');
const propagate = requireWorkflowSource(workflowSources, 'propagate.yml');
const releaseHealth = requireWorkflowSource(workflowSources, 'release-health-monitor.yml');
const releaseHealthIdentityCanary = requireWorkflowSource(workflowSources, 'release-health-monitor-v3.yml');
const releaseHealthFallbackRegistration = requireWorkflowSource(workflowSources, 'release-health-monitor-fallback.yml');
const releaseHealthVerifier = await readSource('scripts', 'verify-org-release-health.mjs');
const releaseHealthRunbook = await readSource('docs', 'RELEASE_HEALTH_GITHUB_APP_RUNBOOK.md');
const propagationRetirementRunbook = await readSource('docs', 'SHARED_PROPAGATION_RETIREMENT.md');
const combined = [...workflowSources.values()].join('\n');

for (const [name, source] of [
  ['renamed-cross-repository-delivery.yaml', 'env:\n  GH_TOKEN: ${{ secrets.SCALESMALL_PAT }}\n'],
  ['future-shared-sync.yml', "env:\n  GH_TOKEN: ${{ secrets['SCALESMALL_PAT'] }}\n"],
]) {
  assert.throws(
    () => assertNoLegacyCrossRepositoryPat(new Map([[name, source]])),
    new RegExp(`${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} references the retired SCALESMALL_PAT identifier`),
    `${name} must not bypass the fleet-wide retired credential guard`,
  );
}
assertNoLegacyCrossRepositoryPat(workflowSources);

requireText(validate, 'permissions:\n  contents: read', 'read-only workflow permissions');
requireText(validate, 'runs-on: ubuntu-24.04', 'pinned validation runner');
requireText(validate, 'persist-credentials: false', 'checkout credential isolation');
requireText(validate, "node-version: '24'", 'current Node runtime');
requireText(validate, 'run: npm run check', 'full shared package check');

const expectedRetiredPropagationSource = [
  'name: Propagate to consumer apps',
  '',
  'on:',
  '  workflow_dispatch:',
  '',
  'permissions: {}',
  '',
  'jobs:',
  '  retired:',
  '    if: ${{ false }}',
  '    runs-on: ubuntu-24.04',
  '    steps:',
  '      - name: Legacy propagation is permanently retired',
  '        run: |',
  '          echo "::error::Legacy shared propagation is permanently retired."',
  '          exit 1',
  '',
].join('\n');
assert.equal(
  propagate,
  expectedRetiredPropagationSource,
  'the legacy propagation workflow must remain the exact inert identity-preserving tombstone',
);
const retiredPropagationSourceSha256 = createHash('sha256').update(propagate).digest('hex');
assert.equal(
  retiredPropagationSourceSha256,
  '28650c6de12cfc94c165b2cb9c3dab1cb6bf1caf8de3815d67cf8bbe6c6b9ba2',
  'the retired propagation tombstone source digest must remain exact',
);
requireText(propagate, 'workflow_dispatch:', 'identity-preserving manual trigger tombstone');
requireText(propagate, 'permissions: {}', 'empty retired workflow permissions');
requireText(propagate, 'if: ${{ false }}', 'unconditionally false retired job gate');
requireText(propagate, 'runs-on: ubuntu-24.04', 'pinned retired workflow runner declaration');
rejectPattern(propagate, /^  (?:push|pull_request|schedule|repository_dispatch):/m, 'retired propagation event trigger');
rejectPattern(propagate, /(?:SCALESMALL_PAT|GH_TOKEN|repos\/ScaleSmall\/(?:SSAI_Connect|SSAI_Dashboard)|\/dispatches\b|gh\s+api\b)/, 'retired propagation credential, consumer, or dispatch path');
requireText(propagationRetirementRunbook, 'workflow identity\n`247016064`', 'retired propagation workflow identity runbook');
requireText(propagationRetirementRunbook, '`disabled_manually` state', 'permanent disabled-state runbook');
requireText(propagationRetirementRunbook, retiredPropagationSourceSha256, 'exact retired tombstone digest runbook');
requireText(propagationRetirementRunbook, 'There is no rollback procedure', 'no-reactivation retirement control');
requireText(propagationRetirementRunbook, 'Delete the `SCALESMALL_PAT` Actions secret', 'repository credential removal gate');
requireText(propagationRetirementRunbook, 'Do not create a replacement cross-repository PAT', 'replacement credential prohibition');
requireText(
  releaseHealthRunbook,
  '[Shared propagation retirement](./SHARED_PROPAGATION_RETIREMENT.md)',
  'release-health runbook pointer to the permanent retired hold',
);
rejectPattern(propagationRetirementRunbook, /gh\s+workflow\s+(?:enable|run)|\/actions\/workflows\/247016064\/(?:enable|dispatches)/i, 'retired propagation reactivation command');

const expectedReleaseHealthIdentityCanarySource = [
  'name: Scale Small AI Release Health Scheduler Identity Canary',
  'run-name: Release health scheduler identity canary [natural]',
  '',
  'on:',
  '  schedule:',
  "    - cron: '1,16,31,46 * * * *'",
  '',
  'concurrency:',
  '  group: scale-small-ai-release-health-monitor-v3-canary',
  '  cancel-in-progress: false',
  '',
  'permissions: {}',
  '',
  'jobs:',
  '  prove-natural-delivery:',
  '    name: Prove natural scheduler delivery',
  "    if: ${{ github.event_name == 'schedule' && github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}",
  '    runs-on: ubuntu-24.04',
  '    timeout-minutes: 2',
  '    steps:',
  '      - name: Verify immutable natural-schedule context',
  '        shell: bash',
  '        env:',
  '          ACTUAL_EVENT: ${{ github.event_name }}',
  '          ACTUAL_REF: ${{ github.ref }}',
  '          ACTUAL_REPOSITORY: ${{ github.repository }}',
  '          ACTUAL_SHA: ${{ github.sha }}',
  '          EXPECTED_REF: refs/heads/${{ github.event.repository.default_branch }}',
  '          EXPECTED_REPOSITORY: ScaleSmall/SSAI_Shared',
  '        run: |',
  '          set -euo pipefail',
  '          if [ "$ACTUAL_EVENT" != \'schedule\' ] || [ "$ACTUAL_REPOSITORY" != "$EXPECTED_REPOSITORY" ] || [ "$ACTUAL_REF" != "$EXPECTED_REF" ] || ! [[ "$ACTUAL_SHA" =~ ^[0-9a-f]{40}$ ]]; then',
  '            echo "::error::Scheduler identity canary received an invalid execution context."',
  '            exit 1',
  '          fi',
  "          printf 'natural_schedule_delivery=verified\\n'",
  "          printf 'repository=%s\\n' \"$ACTUAL_REPOSITORY\"",
  "          printf 'ref=%s\\n' \"$ACTUAL_REF\"",
  "          printf 'sha=%s\\n' \"$ACTUAL_SHA\"",
  '',
].join('\n');

const assertReleaseHealthIdentityCanary = (source) => {
  assert.equal(
    source,
    expectedReleaseHealthIdentityCanarySource,
    'the scheduler identity canary must remain the exact schedule-only inert source',
  );
  rejectPattern(source, /^\s{2}(?:workflow_dispatch|push|pull_request|pull_request_target|repository_dispatch|workflow_call):/m, 'scheduler identity canary non-schedule trigger');
  rejectPattern(source, /\b(?:uses:|secrets\.|github\.token|GITHUB_TOKEN|https?:\/\/|curl\b|wget\b)/i, 'scheduler identity canary credential, action, or network access');
};

assertReleaseHealthIdentityCanary(releaseHealthIdentityCanary);
for (const [description, mutatedSource] of [
  ['manual trigger', releaseHealthIdentityCanary.replace('  schedule:\n', '  workflow_dispatch:\n  schedule:\n')],
  ['repository write permission', releaseHealthIdentityCanary.replace('permissions: {}', 'permissions:\n  contents: write')],
  ['secret access', `${releaseHealthIdentityCanary}# \${{ secrets.UNTRUSTED_SECRET }}\n`],
  ['third-party action', releaseHealthIdentityCanary.replace('    steps:\n', '    steps:\n      - uses: actions/checkout@untrusted\n')],
]) {
  assert.throws(
    () => assertReleaseHealthIdentityCanary(mutatedSource),
    /scheduler identity canary/,
    `the canary contract must reject ${description}`,
  );
}
const releaseHealthIdentityCanarySourceSha256 = createHash('sha256')
  .update(releaseHealthIdentityCanary)
  .digest('hex');
assert.equal(
  releaseHealthIdentityCanarySourceSha256,
  '3fe965ac8e77c17640fbc89633c230639c83d2e4e3ba0d43c9c50195338ce825',
  'the scheduler identity canary source digest must remain exact',
);

const expectedReleaseHealthFallbackRegistrationSource = [
  'name: Scale Small AI Release Health Independent Fallback (Registration)',
  'run-name: Release health independent fallback registration [inert]',
  '',
  'on:',
  '  workflow_dispatch:',
  '',
  'concurrency:',
  '  group: scale-small-ai-release-health-monitor-v2',
  '  cancel-in-progress: false',
  '',
  'permissions: {}',
  '',
  'jobs:',
  '  registration:',
  '    name: Register independent fallback workflow identity',
  '    if: ${{ false }}',
  '    permissions: {}',
  '    runs-on: ubuntu-24.04',
  '    timeout-minutes: 1',
  '    steps:',
  '      - name: Independent fallback remains inert until protected Stage F2',
  '        run: |',
  '          echo "::error::Independent release-health fallback is not activated."',
  '          exit 1',
  '',
].join('\n');

const assertReleaseHealthFallbackRegistration = (source) => {
  assert.equal(
    source,
    expectedReleaseHealthFallbackRegistrationSource,
    'the independent fallback registration must remain the exact inert Stage F1 source',
  );
  rejectPattern(source, /^\s{2}(?:schedule|push|pull_request|pull_request_target|repository_dispatch|workflow_call):/m, 'fallback registration executable event trigger');
  rejectPattern(source, /\b(?:uses:|secrets\.|github\.token|GITHUB_TOKEN|environment:|cache|https?:\/\/|curl\b|wget\b)/i, 'fallback registration credential, action, environment, cache, or network access');
};

assertReleaseHealthFallbackRegistration(releaseHealthFallbackRegistration);
for (const [description, mutatedSource] of [
  ['executable job', releaseHealthFallbackRegistration.replace('if: ${{ false }}', 'if: ${{ true }}')],
  ['native schedule', releaseHealthFallbackRegistration.replace('  workflow_dispatch:\n', "  schedule:\n    - cron: '*/5 * * * *'\n")],
  ['repository dispatch', releaseHealthFallbackRegistration.replace('  workflow_dispatch:', '  repository_dispatch:')],
  ['workflow write permission', releaseHealthFallbackRegistration.replace('permissions: {}', 'permissions:\n  actions: write')],
  ['job write permission', releaseHealthFallbackRegistration.replace('    permissions: {}', '    permissions:\n      contents: write')],
  ['different concurrency group', releaseHealthFallbackRegistration.replace('scale-small-ai-release-health-monitor-v2', 'unregistered-fallback-group')],
  ['environment access', releaseHealthFallbackRegistration.replace('    runs-on: ubuntu-24.04', '    environment: production\n    runs-on: ubuntu-24.04')],
  ['secret access', `${releaseHealthFallbackRegistration}# \${{ secrets.UNTRUSTED_SECRET }}\n`],
  ['action execution', releaseHealthFallbackRegistration.replace('    steps:\n', '    steps:\n      - uses: actions/checkout@untrusted\n')],
  ['network access', releaseHealthFallbackRegistration.replace('          exit 1', '          curl https://example.invalid\n          exit 1')],
]) {
  assert.throws(
    () => assertReleaseHealthFallbackRegistration(mutatedSource),
    /fallback registration/,
    `the Stage F1 contract must reject ${description}`,
  );
}
const releaseHealthFallbackRegistrationSourceSha256 = createHash('sha256')
  .update(releaseHealthFallbackRegistration)
  .digest('hex');
assert.equal(
  releaseHealthFallbackRegistrationSourceSha256,
  '7dc0169828e640614cbced70dc21594ee1cc605118cd81ab5e40cafeab2994ac',
  'the independent fallback registration source digest must remain exact',
);
requireText(releaseHealthRunbook, '## Scheduler identity recovery', 'bounded scheduler identity recovery procedure');
requireText(releaseHealthRunbook, '`.github/workflows/release-health-monitor-v3.yml`', 'replacement workflow path');
requireText(releaseHealthRunbook, releaseHealthIdentityCanarySourceSha256, 'exact canary source digest');
requireText(releaseHealthRunbook, 'Require two successful natural `schedule` runs', 'repeated natural-delivery acceptance gate');
requireText(releaseHealthRunbook, 'Do not leave two full\n   incident writers scheduled', 'single incident-writer cutover gate');
requireText(releaseHealthRunbook, 'require zero queued or in-progress runs', 'drained scheduler cutover gate');
requireText(releaseHealthRunbook, 'Rollback is also protected', 'protected scheduler rollback procedure');
requireText(releaseHealthRunbook, 'Any future hard timing\nrequirement needs a separately reviewed independent scheduler', 'explicit GitHub scheduler service-level boundary');
requireText(releaseHealthRunbook, '## Independent scheduler failover registration', 'bounded independent scheduler failover procedure');
requireText(releaseHealthRunbook, '`.github/workflows/release-health-monitor-fallback.yml`', 'independent fallback workflow path');
requireText(releaseHealthRunbook, releaseHealthFallbackRegistrationSourceSha256, 'exact independent fallback registration digest');
requireText(releaseHealthRunbook, 'Never dispatch Stage F1.', 'inert registration dispatch prohibition');
requireText(releaseHealthRunbook, 'Merge Stage F1 only through exact-head independent approval, hosted validation, and normal branch\nprotection.', 'protected Stage F1 merge gate');
requireText(releaseHealthRunbook, 'record the distinct numeric ID at\nthe exact fallback path and verify state `active`', 'post-merge distinct fallback identity proof');
requireText(releaseHealthRunbook, 'Do not change, dispatch, disable, or reinterpret\nthe existing monitor or native canary', 'native workflow non-mutation boundary');
requireText(releaseHealthRunbook, 'strongly consistent per-slot idempotency', 'independent controller idempotency requirement');
requireText(releaseHealthRunbook, 'Every fallback run must be labeled as fallback', 'fallback provenance boundary');
requireText(releaseHealthRunbook, 'two\nconsecutive exact native `schedule` runs', 'native recovery standby gate');
requireText(releaseHealthRunbook, 'Rollback is ordered: disable controller dispatch first, require zero queued or in-progress fallback\nruns', 'ordered fallback rollback gate');
requireText(releaseHealthRunbook, 'disable the fallback workflow through the official API', 'official fallback disable rollback gate');
requireText(releaseHealthRunbook, 'Preserve run and controller-ledger evidence.', 'fallback rollback evidence preservation');
requireBalancedExpressions(releaseHealthIdentityCanary, 'release-health scheduler identity canary');
requireSpaceIndentation(releaseHealthIdentityCanary, 'release-health scheduler identity canary');
requireBalancedExpressions(releaseHealthFallbackRegistration, 'release-health fallback registration');
requireSpaceIndentation(releaseHealthFallbackRegistration, 'release-health fallback registration');

requireText(releaseHealth, 'workflow_dispatch:', 'manual release-health control');
const releaseHealthCron = '9,24,39,54 * * * *';
requireText(releaseHealth, `cron: '${releaseHealthCron}'`, 'fleet-staggered 15-minute release-health schedule');
const releaseHealthMinutes = [...expandCronMinuteField(releaseHealthCron.split(/\s+/)[0], 'release-health monitor')]
  .sort((left, right) => left - right);
const cyclicReleaseHealthIntervals = releaseHealthMinutes.map((minute, index) => {
  const nextMinute = releaseHealthMinutes[(index + 1) % releaseHealthMinutes.length];
  return (nextMinute - minute + 60) % 60;
});
assert.deepEqual(cyclicReleaseHealthIntervals, [15, 15, 15, 15], 'release-health cadence must remain exactly 15 minutes');
const releaseHealthIdentityCanaryCron = '1,16,31,46 * * * *';
const releaseHealthIdentityCanaryMinutes = [...expandCronMinuteField(
  releaseHealthIdentityCanaryCron.split(/\s+/)[0],
  'release-health scheduler identity canary',
)].sort((left, right) => left - right);
const cyclicReleaseHealthIdentityCanaryIntervals = releaseHealthIdentityCanaryMinutes.map((minute, index) => {
  const nextMinute = releaseHealthIdentityCanaryMinutes[(index + 1) % releaseHealthIdentityCanaryMinutes.length];
  return (nextMinute - minute + 60) % 60;
});
assert.deepEqual(
  cyclicReleaseHealthIdentityCanaryIntervals,
  [15, 15, 15, 15],
  'scheduler identity canary cadence must remain exactly 15 minutes',
);
assert.deepEqual(
  releaseHealthIdentityCanaryMinutes.filter((minute) => releaseHealthMinutes.includes(minute)),
  [],
  'scheduler identity canary must not collide with the current monitor',
);
// Keep these minute fields aligned with every in-scope fleet cron so the monitor
// does not sample partial state while scheduled production work is starting.
const fleetScheduleMinuteReservations = new Map([
  ['SSAI_AI_Audit production-canary.yml', '17 14 * * *'],
  ['SSAI_Analytics_Reporting monthly-reporting.yml monthly', '20 7 1 * *'],
  ['SSAI_Analytics_Reporting monthly-reporting.yml daily', '35 7 * * *'],
  ['SSAI_Analytics_Reporting production-hardening.yml', '37 13 * * *'],
  ['SSAI_Analytics_Reporting production-pages-canary.yml', '17 12 * * *'],
  ['SSAI_CI_Engine production-ci-worker.yml', '7-57/10 * * * *'],
  ['SSAI_Content_Engine production-content-engine-worker.yml', '*/10 * * * *'],
  ['SSAI_Dashboard pull-shared-with-protected-evidence.yml', '11 * * * *'],
  ['SSAI_PoW n8n-production-exactness.yml', '19 */6 * * *'],
  ['SSAI_Production_QA production-service-canaries.yml', '37 * * * *'],
]);
for (const [reservation, cron] of fleetScheduleMinuteReservations) {
  const reservedMinutes = expandCronMinuteField(cron.split(/\s+/)[0], reservation);
  const collisions = releaseHealthMinutes.filter((minute) => reservedMinutes.has(minute));
  if (collisions.length > 0) {
    throw new Error(`Release-health schedule collides with ${reservation} at minute(s): ${collisions.join(', ')}`);
  }
  const canaryCollisions = releaseHealthIdentityCanaryMinutes.filter((minute) => reservedMinutes.has(minute));
  if (canaryCollisions.length > 0) {
    throw new Error(`Scheduler identity canary collides with ${reservation} at minute(s): ${canaryCollisions.join(', ')}`);
  }
}
requireText(releaseHealth, 'permissions:\n  contents: read\n  issues: write', 'bounded same-repository incident delivery permission');
rejectPattern(releaseHealth, /(?:actions|checks|contents|deployments|packages|pull-requests|statuses|workflows): write/, 'unapproved release-health write permission');
requireText(releaseHealth, 'cancel-in-progress: false', 'non-cancelling release-health serialization');
requireText(releaseHealth, 'runs-on: ubuntu-24.04', 'pinned release-health runner');
requireText(releaseHealth, 'persist-credentials: false', 'release-health checkout credential isolation');
requireText(releaseHealth, "node-version: '24'", 'release-health Node runtime');
requireText(releaseHealth, 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1', 'immutable release-health GitHub App token action');
requireText(releaseHealth, 'client-id: ${{ secrets.SSAI_RELEASE_MONITOR_APP_CLIENT_ID }}', 'dedicated release-health GitHub App client ID');
requireText(releaseHealth, 'private-key: ${{ secrets.SSAI_RELEASE_MONITOR_APP_PRIVATE_KEY }}', 'dedicated release-health GitHub App private key');
requireText(releaseHealth, 'owner: ScaleSmall', 'personal-account GitHub App installation owner');
for (const permission of ['actions', 'checks', 'contents', 'deployments', 'metadata', 'pull-requests', 'statuses']) {
  requireText(releaseHealth, `permission-${permission}: read`, `read-only GitHub App ${permission} permission`);
}
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_GITHUB_TOKEN: ${{ steps.release_health_app_token.outputs.token }}', 'short-lived release-health installation token source');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_GITHUB_INSTALLATION_ID: ${{ steps.release_health_app_token.outputs.installation-id }}', 'release-health installation identity gate');
rejectPattern(releaseHealth, /SSAI_RELEASE_MONITOR_READ_TOKEN/, 'unsupported fine-grained PAT release-health source');
rejectPattern(releaseHealth, /SSAI_RELEASE_MONITOR_GITHUB_TOKEN:\s*\$\{\{\s*secrets\.SCALESMALL_PAT\s*\}\}/, 'legacy shared PAT as the release-health token');
rejectPattern(releaseHealth, /skip-token-revoke:\s*['"]?true/i, 'installation token revocation bypass');
requireText(releaseHealth, 'environment:\n      name: release-health-monitor', 'protected release-health environment binding');
requireText(
  releaseHealth,
  "if: ${{ github.event_name != 'workflow_dispatch' || github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}",
  'server-side default-branch manual dispatch gate',
);
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256: ${{ secrets.SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256 }}', 'protected expected-inventory attestation');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_STATE_HMAC_KEY: ${{ secrets.SSAI_RELEASE_MONITOR_STATE_HMAC_KEY }}', 'dedicated protected state HMAC key');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_STATE_HMAC_EPOCH: v1', 'explicit state HMAC epoch');
const verifyJobHeader = releaseHealth.slice(
  releaseHealth.indexOf('  verify:\n'),
  releaseHealth.indexOf('    steps:\n', releaseHealth.indexOf('  verify:\n')),
);
rejectPattern(verifyJobHeader, /secrets\./, 'fleet secrets exposed to job-level actions');
for (const secretName of ['SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256', 'SSAI_RELEASE_MONITOR_STATE_HMAC_KEY']) {
  const references = releaseHealth.match(new RegExp(`secrets\\.${secretName}`, 'g')) || [];
  assert.equal(references.length, 2, `${secretName} must be scoped only to preflight and reconcile steps`);
}
for (const secretName of ['SSAI_RELEASE_MONITOR_APP_CLIENT_ID', 'SSAI_RELEASE_MONITOR_APP_PRIVATE_KEY']) {
  const references = releaseHealth.match(new RegExp(`secrets\\.${secretName}`, 'g')) || [];
  assert.equal(references.length, 1, `${secretName} must be scoped only to the installation-token mint step`);
}
assert.equal(
  (releaseHealth.match(/steps\.release_health_app_token\.outputs\.token/g) || []).length,
  2,
  'the short-lived installation token must be scoped only to preflight and reconcile steps',
);
requireText(releaseHealth, 'scan_mode:', 'explicit continuous/incident release-health mode');
requireText(releaseHealth, 'type: choice', 'validated release-health mode choice');
requireText(releaseHealth, '          - continuous\n          - incident', 'release-health mode options');
requireText(releaseHealth, "run-name: Release health monitor [${{ inputs.scan_mode == 'incident' && 'incident:168h' || format('continuous:{0}h', inputs.lookback_hours || '6') }}]", 'incident-exhaustive release-health run identity');
requireText(releaseHealth, 'lookback_hours:', 'manual release-health lookback control');
requireText(releaseHealth, "default: '6'", 'bounded scheduled release-health lookback default');
requireText(releaseHealth, "timeout-minutes: ${{ inputs.scan_mode == 'incident' && 45 || 12 }}", 'mode-bounded release-health timeout');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_MODE: ${{ inputs.scan_mode || 'continuous' }}", 'release-health scan mode');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_LOOKBACK_HOURS: ${{ inputs.scan_mode == 'incident' && '168' || inputs.lookback_hours || '6' }}", 'forced exhaustive incident lookback');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_MAX_REQUESTS: ${{ inputs.scan_mode == 'incident' && '3500' || '600' }}", 'release-health API request budget');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_RATE_RESERVE: ${{ inputs.scan_mode == 'incident' && '250' || '1000' }}", 'release-health API reserve');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_API_CONCURRENCY: '6'", 'release-health global API concurrency');
requireText(releaseHealth, 'group: scale-small-ai-release-health-monitor-v2', 'orphan-isolated serialized release-health concurrency');
requireText(releaseHealth, 'cancel-in-progress: false', 'non-destructive release-health concurrency');
requireText(releaseHealth, 'actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830', 'pinned scheduled-incident state restore');
requireText(releaseHealth, 'actions/cache/save@0057852bfaa89a56745cba8c7296529d2fc39830', 'pinned scheduled-incident state save');
requireText(releaseHealth, 'ssai-release-health-state-v4-v1-lookup', 'non-sensitive fixed cache lookup key');
requireText(releaseHealth, 'ssai-release-health-state-v4-v1-', 'epoch-bound non-sensitive cache prefix');
requireText(releaseHealth, 'ssai-release-health-state-v3-v1-', 'authenticated previous-state migration restore prefix');
requireText(releaseHealth, 'ssai-release-health-state-v2-v1-', 'authenticated legacy state migration restore prefix');
rejectPattern(releaseHealth, /state-v\d+[^\n]*github\.run_id/, 'source run ID in public cache action key');
requireText(releaseHealth, "if: ${{ github.event_name == 'schedule' }}", 'schedule-only state restore');
requireText(releaseHealth, "always() && github.event_name == 'schedule' && steps.reconcile.outputs.incident_state_changed == 'true'", 'fail-closed changed-state save');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}', 'default-branch state provenance');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_STATE_CACHE_MATCHED_KEY:', 'immutable restored cache identity handoff');
requireText(releaseHealth, 'key: ${{ steps.reconcile.outputs.incident_state_cache_key }}', 'content-digested cache save key');
requireText(releaseHealth, 'id: verify_release_health_state', 'post-save cache visibility verification');
requireText(releaseHealth, 'lookup-only: true', 'side-effect-free cache visibility verification');
requireText(releaseHealth, 'fail-on-cache-miss: true', 'fail-closed missing changed-state cache');
requireText(releaseHealth, 'STATE_CACHE_HIT: ${{ steps.verify_release_health_state.outputs.cache-hit }}', 'cache feature-availability output gate');
requireText(releaseHealth, 'MATCHED_STATE_KEY: ${{ steps.verify_release_health_state.outputs.cache-matched-key }}', 'exact persisted cache identity gate');
requireText(releaseHealth, 'id: require_release_health_state', 'exact persistence assertion outcome gate');
requireText(releaseHealth, '::error::Release-health monitor failed closed', 'generic fail-closed state-persistence error');
rejectPattern(releaseHealth, /Changed release-health incident state was not durably persisted/, 'detailed public state-persistence error');
rejectPattern(releaseHealth, /continue-on-error:\s*true/, 'state restore/save failure suppression');
requireText(releaseHealth, 'notification_reconciliation_required', 'schedule-time incident reconciliation gate');
requireText(releaseHealth, "steps.reconcile.outcome == 'success'", 'successful monitor result before incident reconciliation');
requireText(releaseHealth, "steps.reconcile.outputs.scan_completed == 'true'", 'explicit completed-scan delivery gate');
requireText(releaseHealth, 'steps.verify_release_health_state.outcome == \'success\'', 'delivery after durable state verification');
requireText(releaseHealth, 'steps.require_release_health_state.outcome == \'success\'', 'delivery after exact persistence assertion');
requireText(releaseHealth, "steps.reconcile.outputs.health_degraded == 'true'", 'degraded scheduled conclusion restored after delivery');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_DEFER_DEGRADED_EXIT:', 'scheduled scan and health conclusion decoupling');
requireText(releaseHealth, 'GITHUB_TOKEN: ${{ github.token }}', 'job-scoped same-repository issue token');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_INCIDENT_STATE: ${{ steps.reconcile.outputs.incident_state }}', 'desired managed issue state handoff');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_NOTIFICATION_OUTCOME: ${{ steps.reconcile.outputs.notification_outcome }}', 'allowlisted incident outcome handoff');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_DELIVERY_IDENTITY: ${{ steps.reconcile.outputs.incident_delivery_identity }}', 'durable non-sensitive delivery identity handoff');
requireText(releaseHealth, 'node scripts/sync-release-health-incident-issue.mjs', 'managed issue incident delivery');
requireText(releaseHealth, "await import('./scripts/verify-org-release-health.mjs')", 'workflow-attested dynamic monitor bootstrap');
requireText(releaseHealth, 'executeReleaseHealthMonitorEntryPoint(monitor.runReleaseHealthMonitor)', 'redacted organization release-health entry point');
rejectPattern(releaseHealth, /run:\s*node scripts\/verify-org-release-health\.mjs/, 'unwrapped hosted monitor execution');
requireText(releaseHealthVerifier, 'latestByIdentity(', 'latest current-check selection');
requireText(releaseHealthVerifier, 'evaluateNoHistoryAllowance(', 'evidence-gated manual workflow allowance');
requireText(releaseHealthVerifier, 'collectWorkflowSource(', 'exact no-history workflow source verification');
requireText(releaseHealthVerifier, 'sourceSha256:', 'approved workflow source digest');
requireText(releaseHealthVerifier, 'partitionWorkflowHealth(', 'exhaustive workflow health categorization');
requireText(releaseHealthVerifier, 'workflow_categories_complete', 'workflow category completeness assertion');
requireText(releaseHealthVerifier, 'unresolved_no_history_workflows', 'explicit unresolved no-history accounting');
requireText(releaseHealthVerifier, 'allowed_no_history_evidence', 'auditable no-history evidence summary');
requireText(releaseHealthVerifier, 'verifyAuthorizedDisabledWorkflowHold(', 'source-hashed authorized disabled workflow hold');
requireText(releaseHealthVerifier, 'authorized_disabled_workflow_hold_evidence', 'auditable disabled workflow hold summary');
requireText(releaseHealthVerifier, "if (!isUtf8(source)) throw new Error(repoName + ' workflow source for ' + path + ' is not valid UTF-8.');", 'fail-closed workflow source encoding gate');
requireText(releaseHealthVerifier, "return Buffer.from(source.toString('utf8').replace(/\\r\\n?/g, '\\n'), 'utf8');", 'runtime LF-normalized workflow source digest');
requireText(releaseHealthVerifier, 'verifyForwardFixRecoveryPolicy(', 'source-hashed current-main forward-fix policy');
requireText(releaseHealthVerifier, 'findForwardFixWorkflowRun(', 'bounded cross-trigger workflow forward-fix recovery');
requireText(releaseHealthVerifier, 'findForwardFixCheck(', 'bounded cross-trigger check forward-fix recovery');
const productionQaPolicyFields = [
  ['workflowId: 299211649', 'workflow identity'],
  ["name: 'Production Service Delivery Canaries'", 'workflow name'],
  ["path: '.github/workflows/production-service-canaries.yml'", 'workflow path'],
  ["state: 'disabled_manually'", 'exact authorized disabled state'],
  ["sourceSha256: '50e5c6f7f01364f2b24c7dc7e3082f60959af9b2f048784c73a697677d179591'", 'current-main source digest'],
  ["headRepository: 'ScaleSmall/SSAI_Production_QA'", 'repository boundary'],
  ['reason:', 'explicit hold rationale'],
];
const productionQaPolicyBlock = requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_Production_QA:299211649',
  productionQaPolicyFields,
);
rejectPattern(
  productionQaPolicyBlock,
  /failedEvents|recoveryEvents|jobNames|recoveryDisplayTitles|monitorSelfRecovery/,
  'authorized disabled workflow hold carrying recovery semantics',
);
const retiredPropagationPolicyFields = [
  ['workflowId: 247016064', 'workflow identity'],
  ["name: 'Propagate to consumer apps'", 'workflow name'],
  ["path: '.github/workflows/propagate.yml'", 'workflow path'],
  ["state: 'disabled_manually'", 'exact authorized disabled state'],
  ["sourceSha256: '28650c6de12cfc94c165b2cb9c3dab1cb6bf1caf8de3815d67cf8bbe6c6b9ba2'", 'exact retired tombstone source digest'],
  ["headRepository: 'ScaleSmall/SSAI_Shared'", 'repository boundary'],
  ['reason:', 'explicit permanent-retirement rationale'],
];
const retiredPropagationPolicyBlock = requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_Shared:247016064',
  retiredPropagationPolicyFields,
);
rejectPattern(
  retiredPropagationPolicyBlock,
  /failedEvents|recoveryEvents|jobNames|recoveryDisplayTitles|monitorSelfRecovery/,
  'retired propagation hold carrying recovery semantics',
);
assert.equal(
  (releaseHealthVerifier.match(/SSAI_Shared:247016064/g) || []).length,
  1,
  'the retired propagation hold must have exactly one policy definition',
);
const forwardFixPolicySection = releaseHealthVerifier.slice(
  releaseHealthVerifier.indexOf('const forwardFixRecoveryPolicies = new Map(['),
);
rejectPattern(
  forwardFixPolicySection,
  /SSAI_Production_QA:299211649/,
  'obsolete Production QA forward-fix recovery policy',
);
rejectPattern(
  forwardFixPolicySection,
  /SSAI_Shared:247016064/,
  'retired propagation forward-fix recovery policy',
);
const rrPolicyFields = [
  ['workflowId: 289080389', 'workflow identity'],
  ["path: '.github/workflows/deploy-supabase-functions.yml'", 'workflow path'],
  ["sourceSha256: '203a0ca93974b02a3b97b0ce52f642c991050d8051391f795712e5f0a6d22faa'", 'current-main source digest'],
  ["headRepository: 'ScaleSmall/SSAI_RR'", 'repository boundary'],
  ["failedEvents: ['push']", 'failed trigger boundary'],
  ["recoveryEvents: ['workflow_dispatch']", 'recovery trigger boundary'],
  ["jobNames: ['production-schema-preflight']", 'failed production job boundary'],
  ["recoveryDisplayTitles: ['Deploy R&R Supabase Functions']", 'recovery run identity'],
];
requireRecoveryPolicyBlock(releaseHealthVerifier, 'SSAI_RR:289080389', rrPolicyFields);
assert.throws(
  () => assertRecoveryPolicyFields(
    productionQaPolicyBlock.replace("state: 'disabled_manually'", "state: 'active'"),
    'SSAI_Production_QA:299211649',
    productionQaPolicyFields,
  ),
  /exact authorized disabled state/,
  'a mutated disabled hold state must fail the policy contract',
);
requireText(releaseHealthVerifier, 'findProvisionalForwardFixWorkflowRecovery(', 'bounded forward-fix workflow self-latch');
requireText(releaseHealthVerifier, 'findProvisionalForwardFixCheckRecovery(', 'bounded forward-fix check self-latch');
requireText(releaseHealthVerifier, 'findTrustedMonitorCheckRecovery(', 'source-verified monitor check recovery');
requireText(releaseHealthVerifier, 'findProvisionalTrustedMonitorCheckRecoveryFromRun(', 'check-index-independent monitor self-latch');
requireText(releaseHealthVerifier, 'isTrustedMonitorRecoveryPolicy(', 'explicit trusted-monitor policy gate');
requireText(releaseHealthVerifier, 'isControlledDisabledMonitorRecoveryWorkflow(', 'exact controlled runbook re-disable policy gate');
requireText(releaseHealthVerifier, 'repo.name,\n    allWorkflows,\n    headSha,\n    { recentRuns, defaultBranch },', 'disabled monitor policy resolution without active-health inclusion');
requireText(releaseHealthVerifier, 'findPolicyBoundWorkflowRecovery(', 'coverage-aware workflow recovery selection');
requireText(releaseHealthVerifier, 'findPolicyBoundCheckRecovery(', 'coverage-aware check recovery selection');
requireText(releaseHealthVerifier, 'const directRecovery = trustedMonitorPolicy ? null : policyBoundRecovery;', 'trusted monitor generic-recovery bypass prevention');
requireText(releaseHealthVerifier, "monitorSelfRecoveryContract: 'release-health-monitor-v1'", 'trusted monitor recovery contract');
requireText(releaseHealthVerifier, 'source_run_attempt:', 'exact current run-attempt binding');
requireText(releaseHealthVerifier, "'incident_delivery_identity=' + exactIncidentDeliveryIdentity", 'authenticated stable delivery identity output');
requireText(releaseHealthVerifier, 'incidentDeliveryIdentity: state.delivery_identity', 'restored delivery identity reconciliation');
requireText(releaseHealthVerifier, 'const previousIncidentStateSchema = 3', 'explicit previous-state migration schema');
requireText(releaseHealthVerifier, 'validatePreviousPersistedIncidentState(', 'authenticated v3-to-v4 state migration');
requireText(releaseHealthVerifier, "const previousCachePrefix = 'ssai-release-health-state-v3-'", 'previous-state cache provenance boundary');
requireText(releaseHealthVerifier, 'auditedMonitorOrigins:', 'immutable audited monitor-origin policy');
requireText(releaseHealthVerifier, 'collectMonitorImplementationSource(', 'historical monitor implementation source verification');
requireText(releaseHealthVerifier, 'auditedOriginSources', 'historical workflow/script/utils/delivery digest handoff');
requireText(releaseHealthVerifier, "'scripts/sync-release-health-incident-issue.mjs'", 'source-attested incident delivery implementation');
requireText(releaseHealthVerifier, 'candidates.size * 4', 'four-file trusted monitor source request budget');
requireText(releaseHealthVerifier, 'exact four-file implementation', 'four-file trusted monitor recovery warning');
requireText(releaseHealthVerifier, 'attestTrustedMonitorRecoverySuccesses(', 'durable cross-SHA monitor recovery attestation');
requireText(releaseHealthVerifier, 'maxMonitorImplementationAttestations = 32', 'bounded monitor implementation attestation inventory');
requireText(releaseHealthVerifier, 'maxRecoveryAncestorComparisons = 64', 'bounded recovery ancestor verification inventory');
requireText(releaseHealthVerifier, 'ensureAdditionalRequestBudget(', 'source-attestation request-budget reservation');
requireText(releaseHealthVerifier, '29638546298', 'first exact legacy monitor run identity');
requireText(releaseHealthVerifier, '29704911896', 'source-verified incident failure identity');
requireText(releaseHealthVerifier, '29705959736', 'rate-gated incident failure identity');
requireText(releaseHealthVerifier, '29703046855', 'CI deployment incident failure identity');
requireText(releaseHealthVerifier, '29703666102', 'second rate-gated incident failure identity');
requireText(releaseHealthVerifier, '29706178612', 'transitive monitor incident failure identity');
const auditedMonitorOriginCalls = releaseHealthVerifier.match(/auditedMonitorOrigin\(\d+/g) || [];
if (auditedMonitorOriginCalls.length !== 29) {
  throw new Error(`Expected exactly 29 immutable audited monitor origins; found ${auditedMonitorOriginCalls.length}`);
}
requireText(
  releaseHealthVerifier,
  `export const currentMonitorWorkflowSourceSha256 = '${createHash('sha256').update(releaseHealth).digest('hex')}'`,
  'release-health recovery policy exact normalized workflow digest',
);
requireText(releaseHealthVerifier, 'sourceSha256: currentMonitorWorkflowSourceSha256', 'current monitor policy digest reference');
requireText(
  releaseHealthVerifier,
  "export const auditedPriorMonitorWorkflowSourceSha256 = '3672ed17290279e20d75336e810d9327a59786c16a77332aa5be2f4adb0238a1'",
  'immutable historical monitor workflow digest',
);
requireText(releaseHealthVerifier, 'const excludedRepositories = new Set();', 'empty release-health exclusion set');
requireText(releaseHealthRunbook, 'including `SSAI_Connect`', 'Connect-inclusive GitHub App inventory runbook');
requireText(releaseHealthRunbook, 'update\n`SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256`', 'inventory-digest rotation runbook');
requireText(
  releaseHealthRunbook,
  '1b0f98d54264554fdc81d3f7d5b89e2324f9660ebe15526e49e878d2a932df4b',
  'reviewed Connect-inclusive inventory digest',
);
requireText(releaseHealthRunbook, 'Do not reuse the superseded 20-repository digest', 'superseded inventory rejection');
requireText(releaseHealthRunbook, 'Do not use `workflow_dispatch` as scheduler proof', 'natural scheduler proof runbook');
rejectPattern(releaseHealthRunbook, /Exclude `SSAI_Connect`|Keep the existing `SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256`/, 'stale Connect exclusion or inventory digest instructions');
requireText(releaseHealthVerifier, 'findDeploymentCheckRecovery(', 'cross-trigger deployment recovery proof');
requireText(releaseHealthVerifier, 'findMergedPullCheckRecovery(', 'merged pull-request recovery proof');
requireText(releaseHealthVerifier, 'associateChecksWithPulls(', 'force-pushed pull-request recovery association');
requireText(releaseHealthVerifier, 'findSupersedingCommitStatus(', 'recent classic commit-status recovery selection');
requireText(releaseHealthVerifier, 'findSupersedingDeployment(', 'recent deployment failure recovery selection');
requireText(releaseHealthVerifier, "'/attempts/' + attemptNumber", 'rerun-attempt failure inventory');
requireText(releaseHealthVerifier, 'collectWorkflows(repo.name)', 'paginated workflow inventory');
requireText(releaseHealthVerifier, 'collectBranches(repo.name)', 'independent all-branch commit inventory');
requireText(releaseHealthVerifier, 'collectRecentCommitStatuses(', 'recent classic commit-status inventory');
requireText(releaseHealthVerifier, "identity_source = 'github-actions-job'", 'deployment-to-job stream binding');
requireText(releaseHealthVerifier, 'findPolicyBoundProvisionalWorkflowRecovery(', 'policy-bound workflow self-latch guard');
requireText(releaseHealthVerifier, 'findPolicyBoundProvisionalCheckRecovery(', 'policy-bound check self-latch guard');
requireText(releaseHealthVerifier, 'createConcurrencyGate(apiConcurrency)', 'global GitHub API concurrency gate');
requireText(releaseHealthVerifier, 'GitHub API request budget exhausted', 'fail-closed API request budget');
requireText(releaseHealthVerifier, "await api('/installation/repositories?per_page=1&page=1')", 'installation-authenticated core rate-limit preflight');
requireText(releaseHealthVerifier, "await api('/installation/repositories?per_page=100&page=' + page)", 'installation-scoped repository inventory');
requireText(releaseHealthVerifier, 'validateInstallationRepositoryPage(', 'fail-closed installation pagination validation');
requireText(releaseHealthVerifier, 'verifyInstallationRepositoryScope(', 'least-privilege installation repository scope validation');
rejectPattern(releaseHealthVerifier, /api\('\/user(?:\/repos)?(?:\?|')/, 'PAT-only user repository inventory');
requireText(releaseHealthVerifier, "rateDecision === 'defer'", 'continuous rate-limit backpressure');
requireText(releaseHealthVerifier, "rateDecision === 'fail'", 'incident rate-limit fail-closed gate');
assert.ok(
  releaseHealthVerifier.indexOf('verifyInstallationRepositoryScope(installationRepositories);')
    < releaseHealthVerifier.indexOf('const rateDecision = rateHeadroomDecision('),
  'GitHub App installation scope must fail closed before any quota-deferred return',
);
assert.ok(
  releaseHealthVerifier.indexOf('verifyExpectedInventoryAttestation(repositories, expectedInventorySha256);')
    < releaseHealthVerifier.indexOf('const rateDecision = rateHeadroomDecision('),
  'the exact expected repository inventory must be attested before any quota-deferred return',
);
requireText(releaseHealthVerifier, 'throw truncationError(', 'fail-closed pagination');
requireText(releaseHealthVerifier, 'export function releaseHealthPageLimits(mode)', 'mode-bounded release-health pagination policy');
requireText(releaseHealthVerifier, 'export function releaseHealthCheckPageDisposition(page, batchSize, pageLimit)', 'fail-closed check pagination decision');
requireText(releaseHealthVerifier, 'export function validateReleaseHealthCheckRunPage(', 'validated check-run pagination response');
requireText(releaseHealthVerifier, '!Array.isArray(payload.check_runs)', 'malformed check-run page rejection');
requireText(releaseHealthVerifier, 'checkRun.head_sha !== expectedHeadSha', 'check-run page SHA binding');
requireText(releaseHealthVerifier, 'duplicate check-run identity', 'cross-page check-run identity uniqueness');
requireText(releaseHealthVerifier, "type: 'unageable-current-check-run'", 'fail-closed current-check age attestation');
requireText(releaseHealthVerifier, 'source_run_occurrence_at:', 'source-run occurrence fallback evidence');
requireText(releaseHealthVerifier, 'source_run_activity_at:', 'source-run recent-activity fallback evidence');
requireText(releaseHealthVerifier, 'releaseHealthCheckRecentActivityTime(check)', 'source-run activity separated from occurrence ordering');
requireText(releaseHealthVerifier, 'validateReleaseHealthCheckSourceRun(', 'source-run repository, commit, and identity binding');
requireText(releaseHealthVerifier, 'validateReleaseHealthActionsRunPage(', 'bounded SHA-batched source-run hydration validation');
requireText(releaseHealthVerifier, "'/actions/runs?head_sha='", 'bounded SHA-batched Actions source-run collection');
requireText(releaseHealthVerifier, 'releaseHealthActionsRunHydrationMode(', 'request-minimizing source-run hydration strategy');
requireText(releaseHealthVerifier, "String(check.app?.slug || '') === 'github-actions'", 'GitHub Actions-only source-run provenance');
requireText(releaseHealthVerifier, 'sourceRun.repository?.full_name !== expectedRepository', 'source-run repository binding');
requireText(releaseHealthVerifier, 'check._release_health_current_head === true', 'post-enrichment current-head retention');
requireText(releaseHealthVerifier, 'const currentHead = sha === currentHeadSha;', 'single-pass current-head check classification');
requireText(releaseHealthVerifier, '_release_health_current_head: currentHead', 'unfiltered bounded current-head retention evidence');
assert.ok(
  !releaseHealthVerifier.includes('async function collectCurrentChecks('),
  'current-head checks must not be fetched a second time after the complete all-check pass',
);
requireText(releaseHealthVerifier, "return 'check-run:' + checkRunId", 'unageable failure episode identity');
requireText(releaseHealthVerifier, 'checks: 50', 'bounded 1012+ check-run pagination coverage');
requireText(releaseHealthVerifier, 'fingerprintReleaseHealthIncident(', 'typed immutable incident fingerprinting');
requireText(releaseHealthVerifier, 'decodeScheduledIncidentState(', 'cache-key/content integrity validation');
requireText(releaseHealthVerifier, 'evaluateIncidentNotification(', 'scheduled-only incident notification policy');
requireText(releaseHealthVerifier, 'validateIncidentClusterKey(', 'stable notification cluster validation');
requireText(releaseHealthVerifier, 'failureEpisodeAnchor(', 'success-bounded failure episode identity');
requireText(releaseHealthVerifier, 'evidenceDigestByCluster', 'set-deduplicated stable cluster counting');
requireText(releaseHealthVerifier, 'verifyExpectedInventoryAttestation(', 'protected complete repository inventory attestation');
requireText(releaseHealthVerifier, 'timingSafeEqual(', 'constant-time inventory/state attestation comparison');
requireText(releaseHealthVerifier, 'SSAI_RELEASE_MONITOR_STATE_HMAC_KEY', 'dedicated state HMAC key consumption');
requireText(releaseHealthVerifier, 'decodeScheduledIncidentStateOrNull(', 'safe corrupt-state reinitialization');
requireText(releaseHealthVerifier, 'isExactSelfMonitorEnvironmentDeployment(', 'exact monitor-environment deployment loop exclusion');
requireText(releaseHealthVerifier, 'durableTrustedMonitorRecoveryRuns(', 'manual-only durable workflow recovery filter');
requireText(releaseHealthVerifier, 'durableTrustedMonitorRecoveryChecks(', 'manual-only durable check recovery filter');
requireText(releaseHealthVerifier, 'trustedMonitorPolicy ? durableTrustedMonitorRecoveryRuns(runs, trustedMonitorPolicy, defaultBranch) : runs', 'trusted workflow recovery candidate filtering');
requireText(releaseHealthVerifier, 'trustedMonitorPolicy ? durableTrustedMonitorRecoveryChecks(checks, trustedMonitorPolicy, defaultBranch) : checks', 'trusted check recovery candidate filtering');
requireText(releaseHealthVerifier, '|| !isExactManualIncidentRecoveryRun(run, policy, defaultBranch)', 'manual-only cross-SHA recovery attestation');
requireText(releaseHealthVerifier, "run?.display_title === 'Release health monitor [incident:168h]'", 'exact manual incident durable run identity');
requireText(releaseHealthVerifier, "check?.source_run_display_title === 'Release health monitor [incident:168h]'", 'exact manual incident durable check identity');
requireText(releaseHealthVerifier, "recoveryDisplayTitles: ['Release health monitor [incident:168h]']", 'manual exhaustive trusted-monitor recovery title');
requireText(releaseHealthVerifier, 'isHostedPublicReleaseHealthOutput(environment = process.env)', 'exact hosted-public output boundary');
requireText(releaseHealthVerifier, "String(environment?.GITHUB_ACTIONS || '').toLowerCase() === 'true'", 'all-hosted-Actions redaction boundary');
requireText(releaseHealthVerifier, 'releaseHealthLogPayload(deferredSummary)', 'aggregate-only deferred stdout');
requireText(releaseHealthVerifier, 'releaseHealthLogPayload(summary)', 'aggregate-only completed stdout');
requireText(releaseHealthVerifier, 'renderReleaseHealthStepSummary(result)', 'hosted-public step-summary renderer');
requireText(releaseHealthVerifier, 'executeReleaseHealthMonitorEntryPoint(runReleaseHealthMonitor)', 'redacted direct monitor entry point');
requireText(releaseHealthVerifier, 'Release-health monitor failed closed before aggregate reporting.', 'generic hosted-public fail-closed error');
rejectPattern(releaseHealthVerifier, /console\.log\(JSON\.stringify\((?:deferredSummary|summary),/, 'unredacted release-health JSON stdout');

requireBalancedExpressions(releaseHealth, 'release-health workflow');
requireSpaceIndentation(releaseHealth, 'release-health workflow');

rejectPattern(combined, /ubuntu-latest/, 'floating GitHub runner label');
rejectPattern(combined, /peter-evans\/repository-dispatch@v\d+/i, 'floating repository-dispatch action');
rejectPattern(combined, /^\s*uses:\s+[^@\s]+\/[^@\s]+@v\d+\s*$/im, 'unpinned version-tag action');

console.log('Shared workflow hardening contract verified.');
