import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

const readWorkflow = async (name) =>
  (await readFile(path.join(repoRoot, '.github', 'workflows', name), 'utf8')).replace(/\r\n?|\n/g, '\n');

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
const releaseHealthVerifier = await readSource('scripts', 'verify-org-release-health.mjs');
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
requireText(releaseHealth, "cron: '7,22,37,52 * * * *'", 'staggered 15-minute release-health schedule');
requireText(releaseHealth, 'permissions:\n  contents: read', 'read-only release-health permissions');
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
requireText(releaseHealth, 'actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830', 'pinned scheduled-incident state restore');
requireText(releaseHealth, 'actions/cache/save@0057852bfaa89a56745cba8c7296529d2fc39830', 'pinned scheduled-incident state save');
requireText(releaseHealth, 'ssai-release-health-state-v3-v1-lookup', 'non-sensitive fixed cache lookup key');
requireText(releaseHealth, 'ssai-release-health-state-v3-v1-', 'epoch-bound non-sensitive cache prefix');
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
requireText(releaseHealth, '::error::Release-health monitor failed closed', 'generic fail-closed state-persistence error');
rejectPattern(releaseHealth, /Changed release-health incident state was not durably persisted/, 'detailed public state-persistence error');
rejectPattern(releaseHealth, /continue-on-error:\s*true/, 'state restore/save failure suppression');
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
requireText(releaseHealthVerifier, 'verifyForwardFixRecoveryPolicy(', 'source-hashed current-main forward-fix policy');
requireText(releaseHealthVerifier, 'findForwardFixWorkflowRun(', 'bounded cross-trigger workflow forward-fix recovery');
requireText(releaseHealthVerifier, 'findForwardFixCheck(', 'bounded cross-trigger check forward-fix recovery');
const productionQaPolicyFields = [
  ['workflowId: 299211649', 'workflow identity'],
  ["path: '.github/workflows/production-service-canaries.yml'", 'workflow path'],
  ["sourceSha256: '3df3ef39cc333fe5c3858ebf5352b9d5810324b187d41db599f826005f864c5a'", 'current-main source digest'],
  ["headRepository: 'ScaleSmall/SSAI_Production_QA'", 'repository boundary'],
  ["failedEvents: ['schedule']", 'failed trigger boundary'],
  ["recoveryEvents: ['workflow_dispatch']", 'recovery trigger boundary'],
  ["jobNames: ['End-to-end service delivery canary']", 'failed production job boundary'],
  ["recoveryDisplayTitles: ['Production Service Delivery Canaries']", 'recovery run identity'],
];
const productionQaPolicyBlock = requireRecoveryPolicyBlock(
  releaseHealthVerifier,
  'SSAI_Production_QA:299211649',
  productionQaPolicyFields,
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
    productionQaPolicyBlock.replace("recoveryEvents: ['workflow_dispatch']", "recoveryEvents: ['push']"),
    'SSAI_Production_QA:299211649',
    productionQaPolicyFields,
  ),
  /recovery trigger boundary/,
  'a mutated recovery event must fail the policy contract',
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
requireText(releaseHealthVerifier, 'auditedMonitorOrigins:', 'immutable audited monitor-origin policy');
requireText(releaseHealthVerifier, 'collectMonitorImplementationSource(', 'historical monitor implementation source verification');
requireText(releaseHealthVerifier, 'auditedOriginSources', 'historical workflow/script/utils digest handoff');
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
requireText(releaseHealthVerifier, "const excludedRepositories = new Set(['SSAI_Connect'])", 'protected Connect exclusion');
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
