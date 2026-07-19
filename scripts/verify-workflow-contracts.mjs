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
  const closings = source.match(/\}\}/g)?.length ?? 0;
  if (openings !== closings) throw new Error(`Unbalanced GitHub expressions in ${description}: ${openings}/${closings}`);
};

const requireSpaceIndentation = (source, description) => {
  const tabbedLine = source.split('\n').findIndex((line) => /^\s*\t|\t/.test(line));
  if (tabbedLine >= 0) throw new Error(`${description} contains a tab on line ${tabbedLine + 1}`);
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
requireText(
  propagate,
  "    paths:\n      - 'src/**'\n      - 'package.json'\n      - 'package-lock.json'",
  'package-only automatic propagation scope',
);
const propagationPathBlocks = [...propagate.matchAll(/^    paths:\n((?:      - [^\n]+\n)+)/gm)];
if (propagationPathBlocks.length !== 1) {
  throw new Error(`Expected exactly one automatic propagation path block; found ${propagationPathBlocks.length}`);
}
const automaticPropagationPaths = propagationPathBlocks[0][1]
  .trim()
  .split('\n')
  .map((line) => line.replace(/^\s*-\s*/, '').replace(/^['\"]|['\"]$/g, ''));
const expectedPropagationPaths = ['src/**', 'package.json', 'package-lock.json'];
if (JSON.stringify(automaticPropagationPaths) !== JSON.stringify(expectedPropagationPaths)) {
  throw new Error(
    `Automatic propagation paths must be exactly package-bearing files: ${automaticPropagationPaths.join(', ')}`,
  );
}
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
requireText(releaseHealth, 'scan_mode:', 'explicit continuous/incident release-health mode');
requireText(releaseHealth, 'type: choice', 'validated release-health mode choice');
requireText(releaseHealth, '          - continuous\n          - incident', 'release-health mode options');
requireText(releaseHealth, "run-name: Release health monitor [${{ inputs.scan_mode || 'continuous' }}:${{ inputs.lookback_hours || '6' }}h]", 'input-bound release-health run identity');
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
requireText(releaseHealthVerifier, 'verifyForwardFixRecoveryPolicy(', 'source-hashed current-main forward-fix policy');
requireText(releaseHealthVerifier, 'findForwardFixWorkflowRun(', 'bounded cross-trigger workflow forward-fix recovery');
requireText(releaseHealthVerifier, 'findForwardFixCheck(', 'bounded cross-trigger check forward-fix recovery');
requireText(releaseHealthVerifier, 'findProvisionalForwardFixWorkflowRecovery(', 'bounded forward-fix workflow self-latch');
requireText(releaseHealthVerifier, 'findProvisionalForwardFixCheckRecovery(', 'bounded forward-fix check self-latch');
requireText(releaseHealthVerifier, "const excludedRepositories = new Set(['SSAI_Connect'])", 'protected Connect exclusion');
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

rejectPattern(combined, /ubuntu-latest/, 'floating GitHub runner label');
rejectPattern(combined, /peter-evans\/repository-dispatch@v\d+/i, 'floating repository-dispatch action');
rejectPattern(combined, /^\s*uses:\s+[^@\s]+\/[^@\s]+@v\d+\s*$/im, 'unpinned version-tag action');

console.log('Shared workflow hardening contract verified.');
