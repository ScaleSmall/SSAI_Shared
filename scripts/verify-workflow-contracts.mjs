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

const requireBalancedExpressions = (source, description) => {
  const openings = source.match(/\$\{\{/g)?.length ?? 0;
  const closedExpressions = source.match(/\$\{\{[\s\S]*?\}\}/g)?.length ?? 0;
  if (openings !== closedExpressions) {
    throw new Error(`Unbalanced GitHub expressions in ${description}: ${openings}/${closedExpressions}`);
  }
};

const requireSpaceIndentation = (source, description) => {
  const tabbedLine = source.split('\n').findIndex((line) => /^\s*\t|\t/.test(line));
  if (tabbedLine >= 0) throw new Error(`${description} contains a tab on line ${tabbedLine + 1}`);
};

const validate = await readWorkflow('validate.yml');
const propagate = await readWorkflow('propagate.yml');
const releaseHealth = await readWorkflow('release-health-monitor.yml');
const releaseHealthVerifier = await readFile(path.join(repoRoot, 'scripts', 'verify-org-release-health.mjs'), 'utf8');
const dashboardDispatch = await readFile(path.join(repoRoot, 'scripts', 'dispatch-dashboard-update.mjs'), 'utf8');
const dashboardDispatchTests = await readFile(path.join(repoRoot, 'scripts', 'dispatch-dashboard-update.test.mjs'), 'utf8');
const combined = `${validate}\n${propagate}\n${releaseHealth}`;
const releaseCredentials = await readFile(path.join(repoRoot, 'RELEASE_CREDENTIALS.md'), 'utf8');

requireText(validate, 'permissions:\n  contents: read', 'read-only workflow permissions');
requireText(validate, 'runs-on: ubuntu-24.04', 'pinned validation runner');
requireText(validate, 'persist-credentials: false', 'checkout credential isolation');
requireText(validate, "node-version: '24'", 'current Node runtime');
requireText(validate, 'run: npm run check', 'full shared package check');

requireText(propagate, 'workflow_dispatch:', 'manual propagation control');
requireText(propagate, 'dispatch_connect:', 'protected Connect dispatch gate');
requireText(propagate, 'permissions: {}', 'zero-scope propagation workflow permissions');
requireText(propagate, "group: propagate-consumers-${{ github.repository }}-${{ github.sha }}-${{ github.event_name == 'workflow_dispatch' && inputs.dispatch_connect == 'true' && github.run_id || 'dashboard-only' }}", 'exact-source Dashboard propagation concurrency key with protected Connect isolation');
requireText(propagate, 'cancel-in-progress: false', 'non-cancelling propagation serialization');
requireText(propagate, 'runs-on: ubuntu-24.04', 'pinned propagation runner');
requireText(propagate, 'timeout-minutes: 10', 'bounded propagation timeout');
requireText(propagate, '    permissions:\n      contents: read', 'job-local read-only checkout permission');
requireText(propagate, 'uses: actions/checkout@1af3b93b6815bc44a9784bd300feb67ff0d1eeb3', 'immutable checkout action');
requireText(propagate, 'ref: ${{ github.sha }}', 'exact authoritative Shared checkout');
requireText(propagate, 'persist-credentials: false', 'checkout credential isolation');
requireText(propagate, 'uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e', 'immutable Node setup action');
requireText(propagate, "node-version: '24'", 'current Node runtime');
requireText(propagate, 'Reject historical or non-authoritative producer runs', 'fresh producer guard');
requireText(propagate, "[ \"${RUN_ATTEMPT}\" != '1' ]", 'historical producer rerun rejection');
requireText(propagate, 'start a new workflow_dispatch run from current main', 'fresh-run recovery instruction');
requireText(propagate, 'SSAI_Connect dispatch is intentionally skipped', 'protected Connect skip');
requireText(propagate, "repos/ScaleSmall/SSAI_Connect/dispatches", 'manual Connect dispatch target');
requireText(propagate, "github.event_name == 'workflow_dispatch' && inputs.dispatch_connect == 'true'", 'manual Connect dispatch guard');
requireText(propagate, 'GH_TOKEN: ${{ secrets.SSAI_CONNECT_DISPATCH_TOKEN }}', 'dedicated Connect dispatch token source');
requireText(propagate, 'SSAI_DASHBOARD_DISPATCH_TOKEN: ${{ secrets.SSAI_DASHBOARD_DISPATCH_TOKEN }}', 'dedicated Dashboard dispatch token source');
requireText(propagate, 'node scripts/dispatch-dashboard-update.mjs', 'attested Dashboard dispatch implementation');

const connectStepStart = propagate.indexOf('      - name: Trigger SSAI_Connect rebuild');
const dashboardStepStart = propagate.indexOf('      - name: Attest Dashboard consumer, dispatch v2, and witness a fresh run');
if (connectStepStart < 0 || dashboardStepStart < 0 || dashboardStepStart >= connectStepStart) {
  throw new Error('Missing or misordered protected consumer propagation steps');
}
const dashboardStep = propagate.slice(dashboardStepStart, connectStepStart);
const connectStep = propagate.slice(connectStepStart);

requireText(connectStep, 'set -euo pipefail', 'fail-closed protected Connect propagation shell');
requireText(connectStep, '[ -z "${GH_TOKEN:-}" ]', 'required dedicated Connect token guard');
requireText(connectStep, "[ \"$SOURCE_REPOSITORY\" != 'ScaleSmall/SSAI_Shared' ]", 'Connect source repository guard');
requireText(connectStep, "[ \"$SOURCE_REF\" != 'refs/heads/main' ]", 'Connect source main-ref guard');
requireText(connectStep, '[[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]', 'Connect source SHA guard');
requireText(connectStep, '{event_type:"shared-updated",client_payload:{ref:$sha}}', 'unchanged protected Connect payload contract');
requireText(connectStep, '--input -', 'stdin-bound protected Connect dispatch body');
requireText(connectStep, '--silent', 'non-verbose protected Connect dispatch response');
rejectPattern(connectStep, /client_payload\[[^\]]+\]/, 'Connect dispatch must not use form-encoded payload fields');
rejectPattern(connectStep, /run:\s*\|[\s\S]*\$\{\{\s*github\.(repository|ref|sha)\s*\}\}/, 'GitHub context must enter the Connect shell only through env');
rejectPattern(connectStep, /\bset\s+-[^\n]*x/, 'Connect propagation must not enable shell tracing');

requireText(dashboardStep, 'SSAI_DASHBOARD_DISPATCH_TOKEN: ${{ secrets.SSAI_DASHBOARD_DISPATCH_TOKEN }}', 'bounded Dashboard token injection');
requireText(dashboardStep, 'node scripts/dispatch-dashboard-update.mjs', 'single reviewed Dashboard dispatcher');
rejectPattern(dashboardStep, /\bGH_TOKEN\b/, 'Dashboard step must not expose its credential through GH_TOKEN');
rejectPattern(dashboardStep, /\bSCALESMALL_PAT\b/, 'Dashboard step must not reference the legacy broad PAT');

for (const [expected, description] of [
  ["export const DASHBOARD_REPOSITORY = 'ScaleSmall/SSAI_Dashboard'", 'exact Dashboard repository pin'],
  ["export const DASHBOARD_DEFAULT_BRANCH = 'main'", 'exact Dashboard default-branch pin'],
  ["export const DASHBOARD_MAIN_SHA = 'ca31240527c5a60d3041f8efa41cb8767654db1a'", 'final unified Dashboard SHA pin'],
  ["export const DASHBOARD_WORKFLOW_PATH = '.github/workflows/update-shared.yml'", 'consumer workflow path pin'],
  ["export const DASHBOARD_WORKFLOW_SHA256 = '221bcc96c02dc1f272f8aee663b0d20e71f4cc345b414bbbb835a674a72b3af1'", 'consumer workflow digest pin'],
  ["export const DISPATCH_SCHEMA_VERSION = 2", 'numeric v2 schema pin'],
  ["const ACTIVE_RUN_STATUSES = Object.freeze(['queued', 'in_progress', 'waiting', 'requested', 'pending'])", 'complete nonterminal drain set'],
  ["requireEqual(context.runAttempt, '1'", 'fresh producer attempt guard'],
  ['requireEqual(repository.default_branch, DASHBOARD_DEFAULT_BRANCH', 'default-main attestation'],
  ['requireEqual(object.sha, DASHBOARD_MAIN_SHA', 'Dashboard main SHA attestation'],
  ['requireEqual(sha256(bytes), expectedSha256', 'consumer workflow byte-digest attestation'],
  ["requireEqual(workflow.state, 'active'", 'active consumer state attestation'],
  ['await assertDashboardDrained(api, workflowId)', 'consumer drain attestation'],
  ["event_type: DISPATCH_EVENT_TYPE", 'Dashboard dispatch event'],
  ['schema_version: DISPATCH_SCHEMA_VERSION', 'Dashboard dispatch v2 schema'],
  ['repository: source.repository', 'Dashboard payload repository'],
  ['source_ref: source.ref', 'Dashboard payload source ref'],
  ['sha: source.sha', 'Dashboard payload immutable SHA'],
  ['ref: source.sha', 'Dashboard payload compatibility ref'],
  ['expectedStatus: 204', 'dispatch acceptance contract'],
  ['run_attempt, 1', 'fresh consumer attempt witness'],
  ['Dashboard dispatch produced multiple new consumer runs', 'unique consumer witness'],
  ['no fresh consumer run was witnessed', 'missing consumer witness failure'],
  ['settledWitness.id !== witness.id', 'stable post-dispatch witness'],
]) {
  requireText(dashboardDispatch, expected, description);
}
rejectPattern(dashboardDispatch, /SCALESMALL_PAT/, 'Dashboard dispatcher must never reference the legacy broad PAT');
rejectPattern(dashboardDispatch, /client_payload\s*:\s*\{[^}]*digest/s, 'Dashboard v2 payload must not add an unrecognized digest key');
rejectPattern(dashboardDispatch, /method:\s*'POST'[\s\S]{0,300}\bretr(?:y|ies)\b/i, 'uncertain Dashboard POSTs must never be retried');

for (const expected of [
  'exact five-key numeric-v2 Dashboard dispatch contract',
  'rejects historical producer reruns',
  'exact reviewed Dashboard main commit',
  'exact consumer path, bytes, and SHA-256',
  'exact active consumer workflow marker',
  'nonterminal historical consumer run',
  'exactly one fresh attempt-one run',
  'multiple new runs and stale or rerun witnesses',
  'unreviewed Dashboard commit',
]) {
  requireText(dashboardDispatchTests, expected, `Dashboard dispatcher adversarial test: ${expected}`);
}

requireText(releaseHealth, 'workflow_dispatch:', 'manual release-health control');
requireText(releaseHealth, "cron: '*/15 * * * *'", '15-minute release-health schedule');
requireText(releaseHealth, 'permissions:\n  contents: read', 'read-only release-health permissions');
requireText(releaseHealth, 'cancel-in-progress: false', 'non-cancelling release-health serialization');
requireText(releaseHealth, 'runs-on: ubuntu-24.04', 'pinned release-health runner');
requireText(releaseHealth, 'persist-credentials: false', 'release-health checkout credential isolation');
requireText(releaseHealth, "node-version: '24'", 'release-health Node runtime');
requireText(releaseHealth, 'SSAI_RELEASE_MONITOR_GITHUB_TOKEN: ${{ secrets.SSAI_RELEASE_MONITOR_READ_TOKEN }}', 'dedicated release-health read token source');
requireText(releaseHealth, 'scan_mode:', 'explicit continuous/incident release-health mode');
requireText(releaseHealth, 'type: choice', 'validated release-health mode choice');
requireText(releaseHealth, '          - continuous\n          - incident', 'release-health mode options');
requireText(releaseHealth, 'lookback_hours:', 'manual release-health lookback control');
requireText(releaseHealth, "default: '6'", 'bounded scheduled release-health lookback default');
requireText(releaseHealth, "timeout-minutes: ${{ inputs.scan_mode == 'incident' && 45 || 12 }}", 'mode-bounded release-health timeout');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_MODE: ${{ inputs.scan_mode || 'continuous' }}", 'release-health scan mode');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_LOOKBACK_HOURS: ${{ inputs.lookback_hours || '6' }}", 'release-health failure lookback');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_MAX_REQUESTS: ${{ inputs.scan_mode == 'incident' && '3500' || '600' }}", 'release-health API request budget');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_RATE_RESERVE: ${{ inputs.scan_mode == 'incident' && '250' || '1000' }}", 'release-health API reserve');
requireText(releaseHealth, "SSAI_RELEASE_MONITOR_API_CONCURRENCY: '6'", 'release-health global API concurrency');
requireText(releaseHealth, 'node scripts/verify-org-release-health.mjs', 'organization release-health verifier');
requireText(releaseHealthVerifier, 'latestByIdentity(', 'latest current-check selection');
requireText(releaseHealthVerifier, 'evaluateNoHistoryAllowance(', 'evidence-gated manual workflow allowance');
requireText(releaseHealthVerifier, 'collectWorkflowSource(', 'exact no-history workflow source verification');
requireText(releaseHealthVerifier, 'sourceSha256:', 'approved workflow source digest');
requireText(releaseHealthVerifier, 'partitionWorkflowHealth(', 'exhaustive workflow health categorization');
requireText(releaseHealthVerifier, 'workflow_categories_complete', 'workflow category completeness assertion');
requireText(releaseHealthVerifier, 'unresolved_no_history_workflows', 'explicit unresolved no-history accounting');
requireText(releaseHealthVerifier, 'allowed_no_history_evidence', 'auditable no-history evidence summary');
requireText(releaseHealthVerifier, 'findSupersedingWorkflowRun(', 'recent workflow failure recovery selection');
requireText(releaseHealthVerifier, 'findSupersedingCheck(', 'recent external check failure recovery selection');
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
requireText(releaseHealthVerifier, 'findCurrentSelfRunRecovery(', 'self-latch workflow recovery guard');
requireText(releaseHealthVerifier, 'findCurrentSelfCheckRecovery(', 'self-latch check recovery guard');
requireText(releaseHealthVerifier, 'createConcurrencyGate(apiConcurrency)', 'global GitHub API concurrency gate');
requireText(releaseHealthVerifier, 'GitHub API request budget exhausted', 'fail-closed API request budget');
requireText(releaseHealthVerifier, "await api('/user')", 'representative core rate-limit preflight');
requireText(releaseHealthVerifier, "rateDecision === 'defer'", 'continuous rate-limit backpressure');
requireText(releaseHealthVerifier, "rateDecision === 'fail'", 'incident rate-limit fail-closed gate');
requireText(releaseHealthVerifier, 'throw truncationError(', 'fail-closed pagination');

requireBalancedExpressions(releaseHealth, 'release-health workflow');
requireSpaceIndentation(releaseHealth, 'release-health workflow');
requireBalancedExpressions(propagate, 'propagation workflow');
requireSpaceIndentation(propagate, 'propagation workflow');

rejectPattern(combined, /ubuntu-latest/, 'floating GitHub runner label');
rejectPattern(combined, /SCALESMALL_PAT/, 'broad legacy PAT must not be used by release workflows');
rejectPattern(combined, /peter-evans\/repository-dispatch@v\d+/i, 'floating repository-dispatch action');
rejectPattern(combined, /^\s*uses:\s+[^@\s]+\/[^@\s]+@v\d+\s*$/im, 'unpinned version-tag action');

for (const credential of [
  'SSAI_DASHBOARD_DISPATCH_TOKEN',
  'SSAI_CONNECT_DISPATCH_TOKEN',
  'SSAI_RELEASE_MONITOR_READ_TOKEN',
  'SSAI_DASHBOARD_AUTOMATION_TOKEN',
]) {
  requireText(releaseCredentials, `\`${credential}\``, `documented release credential ${credential}`);
}
requireText(releaseCredentials, 'Never restore `SCALESMALL_PAT` as a fallback', 'legacy broad PAT prohibition');
requireText(releaseCredentials, '`ScaleSmall/SSAI_Shared` is public', 'credentialless public Shared dependency rule');
requireText(releaseCredentials, '`Contents: write` (which includes the required read access) and `Actions: read`', 'least-privilege Dashboard producer token permissions');
requireText(releaseCredentials, '`ca31240527c5a60d3041f8efa41cb8767654db1a`', 'final Dashboard consumer commit interlock');
requireText(releaseCredentials, '`08c6cde1ec084db3e7fc747ee086708965d7e33fd2b667513b14702dd8679993`', 'final Dashboard deterministic build evidence');
requireText(releaseCredentials, '`221bcc96c02dc1f272f8aee663b0d20e71f4cc345b414bbbb835a674a72b3af1`', 'final Dashboard consumer workflow digest interlock');
requireText(releaseCredentials, 'Do not rerun any historical', 'historical producer and consumer rerun prohibition');
requireText(releaseCredentials, '`queued`, `in_progress`, `waiting`', 'complete pre-release workflow drain');
requireText(releaseCredentials, 'delete the Dashboard repository secret named `SCALESMALL_PAT`', 'Dashboard legacy PAT deletion sequence');
requireText(releaseCredentials, "delete Shared's `SCALESMALL_PAT`", 'Shared legacy PAT deletion sequence');
requireText(releaseCredentials, 'post-deletion zero-count drain and secret-name-absence receipt', 'post-deletion credential/drain evidence');
requireText(releaseCredentials, 'The intentionally dropped push event is not replayed', 'disabled-producer release behavior');
requireText(releaseCredentials, 'Never use GitHub\'s rerun button', 'fresh manual producer dispatch requirement');
requireText(releaseCredentials, 'observed twice across the settling', 'stable fresh consumer witness');
requireText(releaseCredentials, 'An uncertain dispatch\nPOST is never retried', 'uncertain dispatch idempotency rule');
requireText(releaseCredentials, 'Never roll back to the legacy direct-', 'safe rollback boundary');

console.log('Shared workflow hardening contract verified.');
