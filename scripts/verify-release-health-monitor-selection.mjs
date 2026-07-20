import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  attestTrustedMonitorImplementation,
  associateChecksWithPulls,
  associateWorkflowRunsWithPulls,
  checkStreamIdentity,
  commitStatusStreamIdentity,
  deploymentJobStreamIdentity,
  deploymentStreamIdentity,
  evaluateNoHistoryAllowance,
  findForwardFixCheck,
  findForwardFixWorkflowRun,
  findPolicyBoundCheckRecovery,
  findPolicyBoundProvisionalCheckRecovery,
  findPolicyBoundProvisionalWorkflowRecovery,
  findPolicyBoundWorkflowRecovery,
  findProvisionalForwardFixCheckRecovery,
  findProvisionalForwardFixWorkflowRecovery,
  findProvisionalTrustedMonitorCheckRecovery,
  findProvisionalTrustedMonitorCheckRecoveryFromRun,
  findProvisionalTrustedMonitorWorkflowRecovery,
  findProvisionalCheckRecovery,
  findProvisionalWorkflowRecovery,
  findDeploymentCheckRecovery,
  findMergedPullCheckRecovery,
  findMergedPullWorkflowRecovery,
  findSupersedingCheck,
  findSupersedingCommitStatus,
  findSupersedingDeployment,
  findSupersedingWorkflowRun,
  findTrustedMonitorCheckRecovery,
  findTrustedMonitorWorkflowRecovery,
  githubRetryDelayMs,
  isTrustedMonitorRecoveryPolicy,
  isEligibleTrustedMonitorImplementationCandidate,
  latestByIdentity,
  partitionWorkflowHealth,
  recordActivityTime,
  rateHeadroomDecision,
  verifyForwardFixRecoveryPolicy,
  workflowStreamIdentity,
} from './release-health-monitor-utils.mjs';

const checks = latestByIdentity([
  { id: 102, name: 'release-health', app: 'github-actions', status: 'in_progress', started_at: '2026-07-18T09:10:00Z' },
  { id: 101, name: 'release-health', app: 'github-actions', status: 'completed', conclusion: 'failure', started_at: '2026-07-18T09:00:00Z' },
  { id: 103, name: 'release-health', app: 'cloudflare', status: 'completed', conclusion: 'success', started_at: '2026-07-18T09:05:00Z' },
], (check) => `${check.app}:${check.name}`);

assert.deepEqual(checks.map((check) => check.id).sort(), [102, 103], 'newer reruns must replace stale failures without merging different check providers');

const statuses = latestByIdentity([
  { id: 201, context: 'Cloudflare Pages', state: 'failure', created_at: '2026-07-18T09:00:00Z' },
  { id: 202, context: 'Cloudflare Pages', state: 'success', created_at: '2026-07-18T09:05:00Z' },
], (status) => status.context);

assert.equal(statuses.length, 1);
assert.equal(statuses[0].state, 'success', 'latest commit status must replace an older state for the same context');
assert.throws(() => latestByIdentity([{}], () => ''), /identity must not be empty/);
assert.equal(rateHeadroomDecision('continuous', 1600, 1000, 600), 'run');
assert.equal(rateHeadroomDecision('continuous', 1599, 1000, 600), 'defer', 'continuous monitoring must back off without creating a failure storm');
assert.equal(rateHeadroomDecision('incident', 3749, 250, 3500), 'fail', 'an explicit incident sweep must fail closed when exhaustive coverage is impossible');
assert.equal(rateHeadroomDecision('incident', 3750, 250, 3500), 'run');
assert.throws(() => rateHeadroomDecision('continuous', -1, 1000, 600), /remaining must be a non-negative integer/);

const retryNowMs = Date.parse('2026-07-20T00:00:00Z');
const ordinaryRateReset = String(Math.floor(retryNowMs / 1000) + 3600);
assert.equal(
  githubRetryDelayMs({
    status: 503,
    retryAfter: null,
    rateLimitRemaining: '4999',
    rateLimitReset: ordinaryRateReset,
    attempt: 1,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  767,
  'a 503 without Retry-After must use bounded backoff and ignore the ordinary rate-reset window',
);
assert.equal(
  githubRetryDelayMs({
    status: 503,
    retryAfter: '2',
    rateLimitRemaining: '4999',
    rateLimitReset: ordinaryRateReset,
    attempt: 1,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  2017,
  'a numeric Retry-After delay must be honored',
);
assert.equal(
  githubRetryDelayMs({
    status: 503,
    retryAfter: new Date(retryNowMs + 5_000).toUTCString(),
    rateLimitRemaining: '4999',
    rateLimitReset: ordinaryRateReset,
    attempt: 1,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  5017,
  'an IMF-fixdate Retry-After delay must be honored',
);
assert.equal(
  githubRetryDelayMs({
    status: 503,
    retryAfter: 'not-a-number',
    rateLimitRemaining: '4999',
    rateLimitReset: ordinaryRateReset,
    attempt: 2,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  1517,
  'a malformed Retry-After value on a 503 must fall back to bounded exponential backoff',
);
assert.equal(
  githubRetryDelayMs({
    status: 503,
    retryAfter: '   ',
    rateLimitRemaining: '4999',
    rateLimitReset: ordinaryRateReset,
    attempt: 1,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  767,
  'a blank Retry-After header must not be coerced to zero',
);
assert.equal(
  githubRetryDelayMs({
    status: 429,
    retryAfter: null,
    rateLimitRemaining: '42',
    rateLimitReset: String(Math.floor(retryNowMs / 1000) + 5),
    attempt: 1,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  5017,
  'a 429 may use the authoritative rate-limit reset timestamp',
);
assert.equal(
  githubRetryDelayMs({
    status: 403,
    retryAfter: null,
    rateLimitRemaining: '0',
    rateLimitReset: String(Math.floor(retryNowMs / 1000) + 5),
    attempt: 1,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  5017,
  'a rate-limited 403 may use the authoritative rate-limit reset timestamp',
);
assert.equal(
  githubRetryDelayMs({
    status: 403,
    retryAfter: null,
    rateLimitRemaining: '1',
    rateLimitReset: String(Math.floor(retryNowMs / 1000) + 5),
    attempt: 1,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  767,
  'a non-rate-limited 403 must not inherit a rate-reset delay',
);
assert.equal(
  githubRetryDelayMs({
    status: 503,
    retryAfter: null,
    rateLimitRemaining: '4999',
    rateLimitReset: ordinaryRateReset,
    attempt: 3,
    maxAttempts: 3,
    nowMs: retryNowMs,
    jitterMs: 17,
  }),
  null,
  'the final attempt must not calculate a retry delay',
);

const workflowPartitions = partitionWorkflowHealth([
  { status: 'completed', conclusion: 'success' },
  { status: 'in_progress', conclusion: null },
  { status: 'completed', conclusion: 'failure' },
  { status: 'no_history', conclusion: 'no_history', allowed_no_history: true },
  { status: 'no_history', conclusion: 'no_history', allowed_no_history: false },
], new Set(['success', 'neutral', 'skipped']));
assert.deepEqual(
  [workflowPartitions.green.length, workflowPartitions.pending.length, workflowPartitions.failed.length,
    workflowPartitions.allowedNoHistory.length, workflowPartitions.unresolvedNoHistory.length, workflowPartitions.categorized],
  [1, 1, 1, 1, 1, 5],
  'workflow summary categories must cover every active workflow exactly once',
);

const manualWorkflow = {
  id: 800,
  name: 'Deploy Production Analytics Pages',
  path: '.github/workflows/deploy-production-pages.yml',
  state: 'active',
};
const witnessWorkflow = {
  id: 801,
  name: 'Production Analytics Pages Canary',
  path: '.github/workflows/production-pages-canary.yml',
  state: 'active',
};
const manualWorkflowSource = 'name: Deploy Production Analytics Pages\non:\n  workflow_dispatch:\n';
const noHistoryPolicy = {
  path: manualWorkflow.path,
  sourceSha256: createHash('sha256').update(manualWorkflowSource).digest('hex'),
  reason: 'Manual releases require a current production canary.',
  witness: {
    name: witnessWorkflow.name,
    path: witnessWorkflow.path,
    headRepository: 'ScaleSmall/SSAI_Analytics_Reporting',
    allowedEvents: ['schedule', 'workflow_dispatch'],
    maxAgeHours: 30,
  },
};
const witnessRun = {
  id: 802,
  workflow_id: witnessWorkflow.id,
  head_branch: 'main',
  head_sha: 'a'.repeat(40),
  head_repository: { full_name: 'ScaleSmall/SSAI_Analytics_Reporting' },
  event: 'workflow_dispatch',
  status: 'completed',
  conclusion: 'success',
  run_started_at: '2026-07-18T13:00:00Z',
  html_url: 'https://github.com/ScaleSmall/SSAI_Analytics_Reporting/actions/runs/802',
};
const noHistoryAllowance = evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: noHistoryPolicy,
  workflowSource: manualWorkflowSource,
  workflows: [manualWorkflow, witnessWorkflow],
  runs: [witnessRun],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
});
assert.equal(noHistoryAllowance.allowed, true, 'manual no-history workflows require exact fresh witness evidence');
assert.equal(noHistoryAllowance.witness?.run_id, witnessRun.id);
assert.equal(noHistoryAllowance.witness?.head_sha, 'a'.repeat(40));
assert.equal(noHistoryAllowance.witness?.event, 'workflow_dispatch');
assert.equal(noHistoryAllowance.witness?.head_repository, 'ScaleSmall/SSAI_Analytics_Reporting');
assert.equal(noHistoryAllowance.witness?.url, witnessRun.html_url);
assert.equal(evaluateNoHistoryAllowance({
  workflow: { ...manualWorkflow, path: '.github/workflows/moved.yml' },
  policy: noHistoryPolicy,
  workflowSource: manualWorkflowSource,
  workflows: [manualWorkflow, witnessWorkflow],
  runs: [witnessRun],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'a moved manual workflow must invalidate its allowance');
assert.equal(evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: noHistoryPolicy,
  workflowSource: manualWorkflowSource,
  workflows: [manualWorkflow, witnessWorkflow],
  runs: [{ ...witnessRun, conclusion: 'failure' }],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'a failed witness must fail closed');
assert.equal(evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: noHistoryPolicy,
  workflowSource: manualWorkflowSource,
  workflows: [manualWorkflow, witnessWorkflow],
  runs: [{ ...witnessRun, run_started_at: '2026-07-16T00:00:00Z' }],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'a stale witness must fail closed');
assert.equal(evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: null,
  workflowSource: manualWorkflowSource,
  workflows: [],
  runs: [],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'unconfigured no-history workflows must fail closed');
assert.equal(evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: {
    path: manualWorkflow.path,
    sourceSha256: createHash('sha256').update(manualWorkflowSource).digest('hex'),
    reason: 'Exact one-shot manual control.',
    witness: false,
  },
  workflowSource: manualWorkflowSource,
  workflows: [manualWorkflow],
  runs: [],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'a falsy witness policy must fail closed');
assert.equal(evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: noHistoryPolicy,
  workflowSource: manualWorkflowSource,
  workflows: [manualWorkflow, witnessWorkflow],
  runs: [witnessRun],
  defaultBranch: 'main',
  expectedHeadSha: 'b'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'witness evidence from a prior main commit must fail closed');
assert.equal(evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: noHistoryPolicy,
  workflowSource: manualWorkflowSource + '# changed semantics\n',
  workflows: [manualWorkflow, witnessWorkflow],
  runs: [witnessRun],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'changed workflow source must invalidate the no-history allowance');
assert.equal(evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: noHistoryPolicy,
  workflowSource: manualWorkflowSource,
  workflows: [manualWorkflow, witnessWorkflow],
  runs: [{ ...witnessRun, event: 'pull_request' }],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'an unapproved witness trigger must fail closed');
assert.equal(evaluateNoHistoryAllowance({
  workflow: manualWorkflow,
  policy: noHistoryPolicy,
  workflowSource: manualWorkflowSource,
  workflows: [manualWorkflow, witnessWorkflow],
  runs: [{ ...witnessRun, head_repository: { full_name: 'untrusted/fork' } }],
  defaultBranch: 'main',
  expectedHeadSha: 'a'.repeat(40),
  nowMs: Date.parse('2026-07-18T14:00:00Z'),
}).allowed, false, 'witness evidence from an unapproved repository must fail closed');

const failedRun = {
  id: 301,
  workflow_id: 44,
  head_branch: 'main',
  head_sha: 'a'.repeat(40),
  event: 'push',
  status: 'completed',
  conclusion: 'failure',
  created_at: '2026-07-18T09:00:00Z',
};
const workflowRecovery = findSupersedingWorkflowRun(failedRun, [
  failedRun,
  { ...failedRun, id: 302, status: 'completed', conclusion: 'skipped', created_at: '2026-07-18T09:02:00Z' },
  { ...failedRun, id: 303, status: 'completed', conclusion: 'success', event: 'workflow_dispatch', created_at: '2026-07-18T09:03:00Z' },
  { ...failedRun, id: 304, status: 'completed', conclusion: 'success', workflow_id: 45, created_at: '2026-07-18T09:04:00Z' },
  { ...failedRun, id: 305, status: 'completed', conclusion: 'success', created_at: '2026-07-18T09:05:00Z' },
]);
assert.equal(workflowRecovery?.id, 305, 'workflow recovery must require the same workflow, branch, and event');
assert.equal(findSupersedingWorkflowRun({ ...failedRun, id: 306, created_at: '2026-07-18T10:00:00Z' }, [failedRun]), null);
assert.match(workflowStreamIdentity({ ...failedRun, head_branch: null }), /sha-/i, 'missing branches must fail closed to the exact SHA');

const forwardFixSource = 'name: Production n8n workflow exactness\non:\n  schedule:\n  workflow_dispatch:\n';
const forwardFixWorkflow = {
  id: 315750527,
  name: 'Production n8n workflow exactness',
  path: '.github/workflows/n8n-production-exactness.yml',
  state: 'active',
};
const forwardFixPolicy = verifyForwardFixRecoveryPolicy({
  workflow: forwardFixWorkflow,
  workflowSource: forwardFixSource,
  policy: {
    workflowId: forwardFixWorkflow.id,
    path: forwardFixWorkflow.path,
    sourceSha256: createHash('sha256').update(forwardFixSource).digest('hex'),
    headRepository: 'ScaleSmall/SSAI_PoW',
    failedEvents: ['schedule'],
    recoveryEvents: ['workflow_dispatch'],
    jobNames: ['verify-production'],
    recoveryDisplayTitles: ['Production n8n workflow exactness'],
  },
});
assert.ok(forwardFixPolicy, 'an exact active source-hashed workflow policy must verify');
assert.equal(isTrustedMonitorRecoveryPolicy(forwardFixPolicy), false, 'a generic forward-fix policy must not enter trusted monitor recovery');
const oldMainSha = '1'.repeat(40);
const currentMainSha = '2'.repeat(40);
const forwardFixFailure = {
  ...failedRun,
  workflow_id: forwardFixWorkflow.id,
  head_sha: oldMainSha,
  head_repository: { full_name: 'ScaleSmall/SSAI_PoW' },
  event: 'schedule',
};
const forwardFixSuccess = {
  ...forwardFixFailure,
  id: 399,
  head_sha: currentMainSha,
  event: 'workflow_dispatch',
  display_title: 'Production n8n workflow exactness',
  status: 'completed',
  conclusion: 'success',
  created_at: '2026-07-18T09:30:00Z',
};
const forwardFixSearch = {
  policy: forwardFixPolicy,
  currentHeadSha: currentMainSha,
  defaultBranch: 'main',
  defaultCommitShas: new Set([oldMainSha, currentMainSha]),
};
assert.equal(
  findForwardFixWorkflowRun(forwardFixFailure, [forwardFixFailure, forwardFixSuccess], forwardFixSearch)?.id,
  399,
  'a source-hashed current-main success may prove an explicitly approved forward fix across trigger types',
);
assert.equal(
  findForwardFixWorkflowRun(
    { ...forwardFixFailure, head_sha: currentMainSha },
    [forwardFixSuccess],
    forwardFixSearch,
  ),
  null,
  'a same-commit manual run must not mask a scheduled failure',
);
assert.equal(verifyForwardFixRecoveryPolicy({
  workflow: forwardFixWorkflow,
  workflowSource: forwardFixSource + '# changed behavior\n',
  policy: {
    workflowId: forwardFixWorkflow.id,
    path: forwardFixWorkflow.path,
    sourceSha256: createHash('sha256').update(forwardFixSource).digest('hex'),
    headRepository: 'ScaleSmall/SSAI_PoW',
    failedEvents: ['schedule'],
    recoveryEvents: ['workflow_dispatch'],
    jobNames: ['verify-production'],
    recoveryDisplayTitles: ['Production n8n workflow exactness'],
  },
}), null, 'changed workflow semantics must disable cross-trigger recovery');

const provisionalForwardFixRun = {
  ...forwardFixSuccess,
  id: 997,
  run_attempt: 1,
  status: 'in_progress',
  conclusion: null,
};
assert.equal(
  findProvisionalForwardFixWorkflowRecovery(
    forwardFixFailure,
    [forwardFixFailure, provisionalForwardFixRun],
    997,
    1,
    forwardFixSearch,
  )?.id,
  997,
  'an exact in-progress forward-fix run may provisionally clear its own predecessor failure',
);
assert.equal(
  findProvisionalForwardFixWorkflowRecovery(
    forwardFixFailure,
    [forwardFixFailure, { ...provisionalForwardFixRun, display_title: 'Release health monitor [incident:168h]' }],
    997,
    1,
    forwardFixSearch,
  ),
  null,
  'an in-progress run with an unapproved display title must not provisionally mask a predecessor failure',
);
assert.equal(
  findProvisionalForwardFixWorkflowRecovery(
    forwardFixFailure,
    [forwardFixFailure, provisionalForwardFixRun],
    996,
    1,
    forwardFixSearch,
  ),
  null,
  'an in-progress run that is not the current run must not provisionally mask a predecessor failure',
);
assert.equal(
  findForwardFixWorkflowRun(
    forwardFixFailure,
    [forwardFixFailure, { ...forwardFixSuccess, display_title: 'Release health monitor [incident:168h]' }],
    forwardFixSearch,
  ),
  null,
  'a terminal run with an unapproved display title must not recover a predecessor failure',
);

const currentRun = { ...failedRun, id: 999, run_attempt: 2, status: 'in_progress', conclusion: null, created_at: '2026-07-18T09:10:00Z' };
assert.equal(
  findProvisionalWorkflowRecovery(failedRun, [failedRun, currentRun], 999, 2)?.id,
  999,
  'the in-progress monitor run must provisionally clear its own previous failure so it can become the recovery',
);
assert.equal(findProvisionalWorkflowRecovery(failedRun, [failedRun, currentRun], 998, 2), null, 'an unrelated run must not suppress a failure');

const monitorSource = 'name: Scale Small AI Release Health Monitor\nrun-name: Release health monitor [mode:hours]\non:\n  schedule:\n  workflow_dispatch:\n';
const monitorWorkflow = {
  id: 315630665,
  name: 'Scale Small AI Release Health Monitor',
  path: '.github/workflows/release-health-monitor.yml',
  state: 'active',
};
const monitorOldSha = '3'.repeat(40);
const monitorCurrentSha = '4'.repeat(40);
const monitorCurrentScriptSource = Buffer.from('console.log("current monitor");\n', 'utf8');
const monitorCurrentUtilsSource = Buffer.from('export const currentMonitor = true;\n', 'utf8');
const monitorVerificationContext = {
  currentHeadSha: monitorCurrentSha,
  monitorImplementationSource: {
    scriptSource: monitorCurrentScriptSource,
    utilsSource: monitorCurrentUtilsSource,
  },
};
const auditedHistoricalWorkflowSource = Buffer.from('name: legacy monitor\non:\n  workflow_dispatch:\n', 'utf8');
const auditedHistoricalScriptSource = Buffer.from('console.log("legacy monitor");\n', 'utf8');
const auditedHistoricalUtilsSource = Buffer.from('export const legacy = true;\n', 'utf8');
const monitorPolicyInput = {
  workflowId: monitorWorkflow.id,
  path: monitorWorkflow.path,
  sourceSha256: createHash('sha256').update(monitorSource).digest('hex'),
  headRepository: 'ScaleSmall/SSAI_Shared',
  failedEvents: ['schedule'],
  recoveryEvents: ['workflow_dispatch'],
  jobNames: ['Verify current organization release health'],
  recoveryDisplayTitles: ['Release health monitor [continuous:6h]'],
  monitorSelfRecoveryContract: 'release-health-monitor-v1',
  monitorSelfRecoveryEvents: ['schedule', 'workflow_dispatch'],
  auditedMonitorOrigins: [{
    runId: 704,
    runAttempt: 1,
    checkRunId: 812,
    headSha: monitorOldSha,
    event: 'workflow_dispatch',
    displayTitle: 'Scale Small AI Release Health Monitor',
    coverageMode: 'continuous',
    coverageHours: 6,
    workflowSourceSha256: createHash('sha256').update(auditedHistoricalWorkflowSource).digest('hex'),
    scriptSourceSha256: createHash('sha256').update(auditedHistoricalScriptSource).digest('hex'),
    utilsSourceSha256: createHash('sha256').update(auditedHistoricalUtilsSource).digest('hex'),
  }, {
    runId: 705,
    runAttempt: 1,
    checkRunId: 813,
    headSha: monitorOldSha,
    event: 'workflow_dispatch',
    displayTitle: 'Release health monitor [incident:168h]',
    coverageMode: 'incident',
    coverageHours: 168,
    coverageStartedAt: '2026-07-18T09:00:00Z',
    workflowSourceSha256: createHash('sha256').update(auditedHistoricalWorkflowSource).digest('hex'),
    scriptSourceSha256: createHash('sha256').update(auditedHistoricalScriptSource).digest('hex'),
    utilsSourceSha256: createHash('sha256').update(auditedHistoricalUtilsSource).digest('hex'),
  }],
};
const auditedOriginSources = new Map([[monitorOldSha, {
  workflowSource: auditedHistoricalWorkflowSource,
  scriptSource: auditedHistoricalScriptSource,
  utilsSource: auditedHistoricalUtilsSource,
}]]);
const monitorPolicy = verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: monitorPolicyInput,
  auditedOriginSources,
});
assert.ok(monitorPolicy, 'trusted monitor recovery requires an exact source-hashed policy');
assert.equal(isTrustedMonitorRecoveryPolicy(monitorPolicy), true, 'the exact monitor policy must enter trusted monitor recovery');
assert.deepEqual(
  [...monitorPolicy.attestedMonitorHeadShas],
  [monitorCurrentSha],
  'a verified policy must initially trust only the exact current implementation SHA',
);
const monitorEquivalentAncestorSha = '6'.repeat(40);
const monitorChangedAncestorSha = '7'.repeat(40);
const monitorDefaultCommitShas = new Set([
  monitorOldSha,
  monitorEquivalentAncestorSha,
  monitorChangedAncestorSha,
  monitorCurrentSha,
]);
const monitorEquivalentAncestorRun = {
  id: 802,
  run_attempt: 1,
  workflow_id: monitorWorkflow.id,
  head_branch: 'main',
  head_sha: monitorEquivalentAncestorSha,
  head_repository: { full_name: 'ScaleSmall/SSAI_Shared' },
  event: 'workflow_dispatch',
  display_title: 'Release health monitor [incident:168h]',
  status: 'completed',
  conclusion: 'success',
  created_at: '2026-07-18T09:20:00Z',
};
assert.equal(attestTrustedMonitorImplementation(monitorPolicy, {
  run: monitorEquivalentAncestorRun,
  defaultBranch: 'main',
  defaultCommitShas: monitorDefaultCommitShas,
  workflowSource: monitorSource,
  scriptSource: monitorCurrentScriptSource,
  utilsSource: monitorCurrentUtilsSource,
}), true, 'an exact three-file implementation match may attest a default-main ancestor');
assert.equal(monitorPolicy.attestedMonitorHeadShas.has(monitorEquivalentAncestorSha), true);
for (const [label, candidateSha, runMutation, defaultCommitShas] of [
  ['fork', '8'.repeat(40), { head_repository: { full_name: 'untrusted/fork' } }, new Set(['8'.repeat(40)])],
  ['non-default branch', '9'.repeat(40), { head_branch: 'feature' }, new Set(['9'.repeat(40)])],
  ['arbitrary workflow', 'a'.repeat(40), { workflow_id: 123 }, new Set(['a'.repeat(40)])],
  ['non-ancestor commit', 'b'.repeat(40), {}, new Set([monitorCurrentSha])],
]) {
  assert.equal(attestTrustedMonitorImplementation(monitorPolicy, {
    run: { ...monitorEquivalentAncestorRun, ...runMutation, id: 805, head_sha: candidateSha },
    defaultBranch: 'main',
    defaultCommitShas,
    workflowSource: monitorSource,
    scriptSource: monitorCurrentScriptSource,
    utilsSource: monitorCurrentUtilsSource,
  }), false, label + ' success must not receive source attestation even when its three files match');
  assert.equal(monitorPolicy.attestedMonitorHeadShas.has(candidateSha), false);
}
assert.equal(attestTrustedMonitorImplementation(monitorPolicy, {
  run: { ...monitorEquivalentAncestorRun, id: 803, head_sha: monitorChangedAncestorSha },
  defaultBranch: 'main',
  defaultCommitShas: monitorDefaultCommitShas,
  workflowSource: monitorSource,
  scriptSource: Buffer.from('console.log("changed ancestor");\n', 'utf8'),
  utilsSource: monitorCurrentUtilsSource,
}), false, 'a changed default-main implementation must not be attested');
for (const [label, mutation] of [
  ['workflow', { workflowSource: monitorSource + '# changed\n' }],
  ['script', { scriptSource: Buffer.from('console.log("changed");\n', 'utf8') }],
  ['utils', { utilsSource: Buffer.from('export const changed = true;\n', 'utf8') }],
  ['missing workflow', { workflowSource: null }],
  ['missing script', { scriptSource: null }],
  ['missing utils', { utilsSource: null }],
]) {
  const rejectedSha = createHash('sha1').update(label).digest('hex');
  const rejectedDefaultCommitShas = new Set([...monitorDefaultCommitShas, rejectedSha]);
  assert.equal(attestTrustedMonitorImplementation(monitorPolicy, {
    run: { ...monitorEquivalentAncestorRun, id: 804, head_sha: rejectedSha },
    defaultBranch: 'main',
    defaultCommitShas: rejectedDefaultCommitShas,
    workflowSource: monitorSource,
    scriptSource: monitorCurrentScriptSource,
    utilsSource: monitorCurrentUtilsSource,
    ...mutation,
  }), false, label + ' mismatch or absence must fail closed');
  assert.equal(monitorPolicy.attestedMonitorHeadShas.has(rejectedSha), false);
}
assert.equal(verifyForwardFixRecoveryPolicy({
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: monitorPolicyInput,
  auditedOriginSources,
  currentHeadSha: monitorCurrentSha,
  monitorImplementationSource: { scriptSource: monitorCurrentScriptSource, utilsSource: null },
}), null, 'a trusted current policy must fail closed when any implementation source is missing');
assert.equal(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: { ...monitorPolicyInput, monitorSelfRecoveryEvents: [] },
  auditedOriginSources,
}), null, 'an empty trusted monitor event set must fail closed');
assert.equal(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: monitorPolicyInput,
}), null, 'audited monitor origins must fail closed when historical source evidence is unavailable');
assert.equal(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: monitorPolicyInput,
  auditedOriginSources: new Map([[monitorOldSha, {
    workflowSource: auditedHistoricalWorkflowSource,
    scriptSource: auditedHistoricalScriptSource,
    utilsSource: Buffer.from('tampered\n', 'utf8'),
  }]]),
}), null, 'a historical implementation digest mismatch must invalidate the entire recovery policy');
const absentUtilsPolicyInput = {
  ...monitorPolicyInput,
  auditedMonitorOrigins: [{
    ...monitorPolicyInput.auditedMonitorOrigins[0],
    utilsSourceSha256: null,
  }],
};
assert.ok(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: absentUtilsPolicyInput,
  auditedOriginSources: new Map([[monitorOldSha, {
    workflowSource: auditedHistoricalWorkflowSource,
    scriptSource: auditedHistoricalScriptSource,
    utilsSource: null,
  }]]),
}), 'an audited historical absence must be verified as an exact null source');
assert.equal(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: absentUtilsPolicyInput,
  auditedOriginSources,
}), null, 'a file appearing where historical absence was asserted must invalidate the policy');
assert.equal(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: {
    ...monitorPolicyInput,
    auditedMonitorOrigins: monitorPolicyInput.auditedMonitorOrigins.map((origin, index) => (
      index === 0 ? { ...origin, checkRunId: 0 } : origin
    )),
  },
  auditedOriginSources,
}), null, 'an invalid audited check identity must fail closed');
const monitorSearch = {
  policy: monitorPolicy,
  currentHeadSha: monitorCurrentSha,
  defaultBranch: 'main',
  defaultCommitShas: monitorDefaultCommitShas,
};
const scheduledMonitorFailure = {
  ...failedRun,
  id: 701,
  workflow_id: monitorWorkflow.id,
  head_sha: monitorOldSha,
  head_repository: { full_name: 'ScaleSmall/SSAI_Shared' },
  event: 'schedule',
  display_title: 'Release health monitor [continuous:6h]',
  created_at: '2026-07-18T09:00:00Z',
};
const manualContinuousMonitorFailure = {
  ...scheduledMonitorFailure,
  id: 702,
  head_sha: monitorCurrentSha,
  event: 'workflow_dispatch',
  created_at: '2026-07-18T09:01:00Z',
};
const manualIncidentMonitorFailure = {
  ...manualContinuousMonitorFailure,
  id: 703,
  display_title: 'Release health monitor [incident:168h]',
  created_at: '2026-07-18T09:02:00Z',
};
const currentIncidentMonitorRun = {
  ...manualIncidentMonitorFailure,
  id: 799,
  run_attempt: 2,
  status: 'in_progress',
  conclusion: null,
  created_at: '2026-07-18T09:10:00Z',
};
const currentScheduledMonitorRun = {
  ...manualContinuousMonitorFailure,
  id: 798,
  run_attempt: 1,
  event: 'schedule',
  status: 'in_progress',
  conclusion: null,
  created_at: '2026-07-18T09:09:00Z',
};
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    scheduledMonitorFailure,
    [scheduledMonitorFailure, currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  )?.id,
  799,
  'an exact current incident scan may self-latch an older scheduled monitor failure',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    manualContinuousMonitorFailure,
    [manualContinuousMonitorFailure, currentScheduledMonitorRun],
    798,
    1,
    monitorSearch,
  )?.id,
  798,
  'the exact current in-progress six-hour scan may provisionally supersede an earlier equal-width scan',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, { ...currentScheduledMonitorRun, id: 797 }],
    797,
    1,
    monitorSearch,
  ),
  null,
  'a continuous scan must not claim recovery of a broader incident scan',
);
const currentManualContinuousMonitorRun = {
  ...currentScheduledMonitorRun,
  id: 796,
  event: 'workflow_dispatch',
  created_at: '2026-07-18T09:11:00Z',
};
const completedManualContinuousMonitorRun = {
  ...currentManualContinuousMonitorRun,
  id: 795,
  status: 'completed',
  conclusion: 'success',
  created_at: '2026-07-18T09:12:00Z',
};
assert.equal(
  findSupersedingWorkflowRun(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, completedManualContinuousMonitorRun],
  )?.id,
  795,
  'the generic same-trigger selector demonstrates why trusted monitor policy binding is required',
);
assert.equal(
  findPolicyBoundWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, completedManualContinuousMonitorRun],
    monitorPolicy,
    monitorSearch,
  ),
  null,
  'the actual policy-bound workflow selector must reject narrower same-trigger recovery',
);
assert.equal(
  findPolicyBoundProvisionalWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, currentManualContinuousMonitorRun],
    796,
    1,
    monitorPolicy,
    monitorSearch,
  ),
  null,
  'the actual policy-bound workflow self-latch must reject a narrower same-trigger scan',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    scheduledMonitorFailure,
    [scheduledMonitorFailure, currentIncidentMonitorRun],
    799,
    1,
    monitorSearch,
  ),
  null,
  'a prior run attempt must not self-latch the current monitor attempt',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    scheduledMonitorFailure,
    [scheduledMonitorFailure, { ...currentIncidentMonitorRun, head_repository: { full_name: 'untrusted/fork' } }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a fork run must not recover a trusted monitor failure',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    scheduledMonitorFailure,
    [scheduledMonitorFailure, { ...currentIncidentMonitorRun, display_title: 'Release health monitor [incident:169h]' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'an out-of-contract scan title must fail closed',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  )?.id,
  799,
  'a lone shifted incident failure may be provisionally recovered by the exact current equal-width incident rescan',
);
const repeatedIncidentMonitorFailure = {
  ...manualIncidentMonitorFailure,
  id: 721,
  created_at: '2026-07-18T09:05:00Z',
};
for (const origin of [manualIncidentMonitorFailure, repeatedIncidentMonitorFailure]) {
  assert.equal(
    findProvisionalTrustedMonitorWorkflowRecovery(
      origin,
      [manualIncidentMonitorFailure, repeatedIncidentMonitorFailure, currentIncidentMonitorRun],
      799,
      2,
      monitorSearch,
    )?.id,
    799,
    'repeated equal-width incident failures must not form a permanent self-recovery deadlock',
  );
}
const chainedContinuousMonitorFailure = {
  ...manualContinuousMonitorFailure,
  id: 722,
  created_at: '2026-07-18T09:06:00Z',
};
for (const origin of [manualIncidentMonitorFailure, chainedContinuousMonitorFailure]) {
  assert.equal(
    findProvisionalTrustedMonitorWorkflowRecovery(
      origin,
      [manualIncidentMonitorFailure, chainedContinuousMonitorFailure, currentIncidentMonitorRun],
      799,
      2,
      monitorSearch,
    )?.id,
    799,
    'an incident failure followed by a continuous failure must be recoverable by the exact current incident rescan',
  );
}
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, status: 'completed', conclusion: 'failure' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a completed current run must never receive provisional self-recovery authority',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, status: 'queued' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a queued run has not begun the independent rescan and must not receive provisional recovery authority',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, head_sha: monitorOldSha }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a run that is not executing the exact verified current-main source must fail closed',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, head_sha: monitorEquivalentAncestorSha }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'an attested ancestor may provide terminal recovery but must never impersonate the current provisional run',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, display_title: 'Release health monitor [incident:167h]' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a narrower incident window must not provisionally recover a broader incident failure',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    { ...manualIncidentMonitorFailure, workflow_id: 123 },
    [currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  ),
  null,
  'an arbitrary workflow failure must remain outside provisional trusted monitor recovery',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    { ...manualIncidentMonitorFailure, head_sha: '5'.repeat(40) },
    [currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a failure whose source commit is not verified on the default branch must fail closed',
);
const completedIncidentMonitorRun = {
  ...currentIncidentMonitorRun,
  id: 800,
  run_attempt: 1,
  status: 'completed',
  conclusion: 'success',
  created_at: '2026-07-18T09:20:00Z',
};
const ancestorIncidentMonitorSuccess = {
  ...completedIncidentMonitorRun,
  id: 802,
  head_sha: monitorEquivalentAncestorSha,
};
assert.equal(isEligibleTrustedMonitorImplementationCandidate(
  ancestorIncidentMonitorSuccess,
  monitorPolicy,
  { defaultBranch: 'main', defaultCommitShas: monitorSearch.defaultCommitShas },
), true, 'an exact successful monitor run on an attested default-main ancestor is an eligible source candidate');
for (const mutation of [
  { workflow_id: 123 },
  { head_repository: { full_name: 'untrusted/fork' } },
  { head_branch: 'feature' },
  { event: 'push' },
  { display_title: 'unverified monitor title' },
  { status: 'in_progress', conclusion: null },
  { conclusion: 'failure' },
]) {
  assert.equal(isEligibleTrustedMonitorImplementationCandidate(
    { ...ancestorIncidentMonitorSuccess, ...mutation },
    monitorPolicy,
    { defaultBranch: 'main', defaultCommitShas: monitorSearch.defaultCommitShas },
  ), false, 'arbitrary, forked, non-default, or unsuccessful monitor candidates must fail closed');
}
assert.equal(isEligibleTrustedMonitorImplementationCandidate(
  ancestorIncidentMonitorSuccess,
  monitorPolicy,
  { defaultBranch: 'main', defaultCommitShas: new Set([monitorCurrentSha]) },
), false, 'matching source bytes on a non-default commit must not authorize ancestor recovery');
const auditedLegacyMonitorFailure = {
  ...manualContinuousMonitorFailure,
  id: 704,
  run_attempt: 1,
  head_sha: monitorOldSha,
  event: 'workflow_dispatch',
  display_title: 'Scale Small AI Release Health Monitor',
  created_at: '2026-07-18T09:01:00Z',
};
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    auditedLegacyMonitorFailure,
    [auditedLegacyMonitorFailure, currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  )?.id,
  799,
  'an exhaustive incident may provisionally cover an exact source-audited legacy six-hour origin',
);
for (const mutation of [
  { id: 706 },
  { run_attempt: 2 },
  { head_sha: '5'.repeat(40) },
  { event: 'schedule' },
  { display_title: 'Scale Small AI Release Health Monitor ' },
  { head_repository: { full_name: 'untrusted/fork' } },
  { head_branch: 'feature' },
]) {
  assert.equal(
    findProvisionalTrustedMonitorWorkflowRecovery(
      { ...auditedLegacyMonitorFailure, ...mutation },
      [currentIncidentMonitorRun],
      799,
      2,
      monitorSearch,
    ),
    null,
    'every immutable audited workflow identity field must match exactly',
  );
}
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    auditedLegacyMonitorFailure,
    [auditedLegacyMonitorFailure, currentScheduledMonitorRun],
    798,
    1,
    monitorSearch,
  )?.id,
  798,
  'an exact audited six-hour origin may be provisionally recovered by the current equal-width scan',
);
const auditedPriorIncidentFailure = {
  ...manualIncidentMonitorFailure,
  id: 705,
  run_attempt: 1,
  head_sha: monitorOldSha,
};
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    auditedPriorIncidentFailure,
    [auditedPriorIncidentFailure, currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  )?.id,
  799,
  'an exact evidence-bound incident origin may use its narrower proven predicate cutoff',
);
assert.equal(
  findProvisionalTrustedMonitorWorkflowRecovery(
    { ...auditedPriorIncidentFailure, id: 706 },
    [currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  )?.id,
  799,
  'a modern source-verified incident origin may use nominal coverage during the exact current rescan',
);
assert.equal(
  findTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, completedIncidentMonitorRun],
    monitorSearch,
  )?.id,
  800,
  'a successful exact source-verified incident must durably recover an earlier equal-width incident failure',
);
const ancestorIncidentMonitorFailure = {
  ...manualIncidentMonitorFailure,
  id: 723,
  head_sha: monitorEquivalentAncestorSha,
};
assert.equal(
  findTrustedMonitorWorkflowRecovery(
    ancestorIncidentMonitorFailure,
    [ancestorIncidentMonitorFailure, ancestorIncidentMonitorSuccess],
    monitorSearch,
  )?.id,
  802,
  'a successful equivalent implementation at SHA A must durably recover after default main advances to SHA B',
);
const laterCurrentContinuousMonitorRun = {
  ...currentManualContinuousMonitorRun,
  id: 794,
  event: 'schedule',
  created_at: '2026-07-18T09:30:00Z',
};
assert.equal(
  findPolicyBoundWorkflowRecovery(
    ancestorIncidentMonitorFailure,
    [ancestorIncidentMonitorFailure, ancestorIncidentMonitorSuccess, laterCurrentContinuousMonitorRun],
    monitorPolicy,
    monitorSearch,
  )?.id,
  802,
  'a scheduled six-hour scan at SHA B must inherit the attested SHA A success instead of reopening the old failure',
);
assert.equal(
  findTrustedMonitorWorkflowRecovery(
    ancestorIncidentMonitorFailure,
    [ancestorIncidentMonitorFailure, {
      ...ancestorIncidentMonitorSuccess,
      id: 803,
      head_sha: monitorChangedAncestorSha,
    }],
    monitorSearch,
  ),
  null,
  'a default-main ancestor success with changed implementation bytes must not recover across SHAs',
);
assert.equal(
  findTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, {
      ...completedIncidentMonitorRun,
      id: 801,
      display_title: 'Release health monitor [incident:167h]',
      created_at: '2026-07-18T09:21:00Z',
    }],
    monitorSearch,
  ),
  null,
  'a successful but narrower incident must not durably recover a broader incident failure',
);
assert.equal(
  findTrustedMonitorWorkflowRecovery(
    { ...scheduledMonitorFailure, workflow_id: 123 },
    [completedIncidentMonitorRun],
    monitorSearch,
  ),
  null,
  'an arbitrary workflow failure must never use trusted monitor recovery',
);

const failedDeployment = {
  id: 401,
  deployment_id: 40,
  environment: 'production',
  stream_identity: 'deployment:production:workflow-1:deploy-rr-send-outreach',
  state: 'failure',
  created_at: '2026-07-18T09:00:00Z',
};
const deploymentRecovery = findSupersedingDeployment(failedDeployment, [
  failedDeployment,
  { ...failedDeployment, id: 402, deployment_id: 41, stream_identity: 'deployment:production:workflow-1:deploy-rr-referral', state: 'success', created_at: '2026-07-18T09:02:00Z' },
  { ...failedDeployment, id: 403, deployment_id: 42, state: 'pending', created_at: '2026-07-18T09:03:00Z' },
  { ...failedDeployment, id: 404, deployment_id: 43, state: 'success', created_at: '2026-07-18T09:04:00Z' },
]);
assert.equal(deploymentRecovery?.id, 404, 'deployment recovery must require the same job stream, not merely the same environment');
assert.equal(findSupersedingDeployment({ ...failedDeployment, id: 405, created_at: '2026-07-18T10:00:00Z' }, [failedDeployment]), null);
assert.notEqual(
  deploymentStreamIdentity({ deployment_id: 1, environment: 'production' }),
  deploymentStreamIdentity({ deployment_id: 2, environment: 'production' }),
  'deployments without stable job metadata must fail closed to their own deployment ID',
);
const failedCheck = {
  id: 501,
  name: 'verify',
  app: { slug: 'github-actions' },
  workflow_id: 100,
  event: 'push',
  head_branch: 'main',
  head_sha: 'b'.repeat(40),
  status: 'completed',
  conclusion: 'failure',
  started_at: '2026-07-18T09:00:00Z',
};
const forwardFixFailedCheck = {
  ...failedCheck,
  workflow_id: forwardFixWorkflow.id,
  name: 'verify-production',
  event: 'schedule',
  head_sha: oldMainSha,
  head_repository: 'ScaleSmall/SSAI_PoW',
};
const forwardFixSuccessfulCheck = {
  ...forwardFixFailedCheck,
  id: 598,
  event: 'workflow_dispatch',
  head_sha: currentMainSha,
  source_run_display_title: 'Production n8n workflow exactness',
  conclusion: 'success',
  started_at: '2026-07-18T09:30:00Z',
};
assert.equal(
  findForwardFixCheck(forwardFixFailedCheck, [forwardFixFailedCheck, forwardFixSuccessfulCheck], forwardFixSearch)?.id,
  598,
  'only an approved job on the exact current-main forward fix may recover a cross-trigger check',
);
assert.equal(
  findForwardFixCheck(
    { ...forwardFixFailedCheck, name: 'dry-run' },
    [{ ...forwardFixSuccessfulCheck, name: 'dry-run' }],
    forwardFixSearch,
  ),
  null,
  'an unapproved dry-run job must never mask a production check failure',
);
const provisionalForwardFixCheck = {
  ...forwardFixSuccessfulCheck,
  id: 597,
  source_run_id: 997,
  status: 'in_progress',
  conclusion: null,
};
assert.equal(
  findProvisionalForwardFixCheckRecovery(
    forwardFixFailedCheck,
    [forwardFixFailedCheck, provisionalForwardFixCheck],
    997,
    1,
    forwardFixSearch,
  )?.id,
  597,
  'the exact current forward-fix check may provisionally clear its own predecessor failure',
);
assert.equal(
  findProvisionalForwardFixCheckRecovery(
    forwardFixFailedCheck,
    [
      forwardFixFailedCheck,
      { ...provisionalForwardFixCheck, source_run_display_title: 'Release health monitor [incident:168h]' },
    ],
    997,
    1,
    forwardFixSearch,
  ),
  null,
  'an in-progress check from a run with an unapproved display title must not mask a predecessor failure',
);
assert.equal(
  findProvisionalForwardFixCheckRecovery(
    forwardFixFailedCheck,
    [forwardFixFailedCheck, provisionalForwardFixCheck],
    996,
    1,
    forwardFixSearch,
  ),
  null,
  'an in-progress check from a different current run must not mask a predecessor failure',
);
assert.equal(
  findForwardFixCheck(
    forwardFixFailedCheck,
    [
      forwardFixFailedCheck,
      { ...forwardFixSuccessfulCheck, source_run_display_title: 'Release health monitor [incident:168h]' },
    ],
    forwardFixSearch,
  ),
  null,
  'a terminal check from a run with an unapproved display title must not recover a predecessor failure',
);

const scheduledMonitorFailedCheck = {
  ...failedCheck,
  id: 810,
  workflow_id: monitorWorkflow.id,
  name: 'Verify current organization release health',
  event: 'schedule',
  head_sha: monitorOldSha,
  head_repository: 'ScaleSmall/SSAI_Shared',
  source_run_display_title: 'Release health monitor [continuous:6h]',
  started_at: '2026-07-18T09:00:00Z',
};
const incidentMonitorFailedCheck = {
  ...scheduledMonitorFailedCheck,
  id: 811,
  event: 'workflow_dispatch',
  head_sha: monitorCurrentSha,
  source_run_display_title: 'Release health monitor [incident:168h]',
  started_at: '2026-07-18T09:02:00Z',
};
const currentIncidentMonitorCheck = {
  ...incidentMonitorFailedCheck,
  id: 899,
  source_run_id: 799,
  source_run_attempt: 2,
  status: 'in_progress',
  conclusion: null,
  started_at: '2026-07-18T09:10:00Z',
};
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, currentIncidentMonitorCheck],
    799,
    2,
    monitorSearch,
  )?.id,
  899,
  'a lone shifted incident check may be provisionally recovered by the exact current equal-width incident job',
);
const repeatedIncidentMonitorFailedCheck = {
  ...incidentMonitorFailedCheck,
  id: 820,
  source_run_id: 721,
  started_at: '2026-07-18T09:05:00Z',
};
for (const origin of [incidentMonitorFailedCheck, repeatedIncidentMonitorFailedCheck]) {
  assert.equal(
    findProvisionalTrustedMonitorCheckRecovery(
      origin,
      [incidentMonitorFailedCheck, repeatedIncidentMonitorFailedCheck, currentIncidentMonitorCheck],
      799,
      2,
      monitorSearch,
    )?.id,
    899,
    'repeated equal-width incident check failures must not form a permanent self-recovery deadlock',
  );
}
const chainedContinuousMonitorFailedCheck = {
  ...scheduledMonitorFailedCheck,
  id: 821,
  source_run_id: 722,
  event: 'workflow_dispatch',
  head_sha: monitorCurrentSha,
  started_at: '2026-07-18T09:06:00Z',
};
for (const origin of [incidentMonitorFailedCheck, chainedContinuousMonitorFailedCheck]) {
  assert.equal(
    findProvisionalTrustedMonitorCheckRecovery(
      origin,
      [incidentMonitorFailedCheck, chainedContinuousMonitorFailedCheck, currentIncidentMonitorCheck],
      799,
      2,
      monitorSearch,
    )?.id,
    899,
    'incident and continuous monitor checks must both be recoverable by the exact current incident job',
  );
}
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, { ...currentIncidentMonitorCheck, status: 'completed', conclusion: 'failure' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a completed current check must never receive provisional self-recovery authority',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, { ...currentIncidentMonitorCheck, status: 'queued' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a queued check has not begun the independent rescan and must not receive provisional recovery authority',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, { ...currentIncidentMonitorCheck, head_sha: monitorOldSha }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a current check that is not bound to the verified current-main source must fail closed',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, { ...currentIncidentMonitorCheck, head_sha: monitorEquivalentAncestorSha }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'an attested ancestor check must never impersonate the exact current provisional check',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, { ...currentIncidentMonitorCheck, head_repository: 'untrusted/fork' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a current check from an unrelated repository stream must fail closed',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, { ...currentIncidentMonitorCheck, source_run_display_title: 'Release health monitor [incident:167h]' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a narrower incident check window must not recover a broader incident check failure',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    { ...incidentMonitorFailedCheck, app: { slug: 'external-provider' } },
    [currentIncidentMonitorCheck],
    799,
    2,
    monitorSearch,
  ),
  null,
  'an external-provider check must remain outside provisional trusted monitor recovery',
);
const auditedLegacyMonitorFailedCheck = {
  ...scheduledMonitorFailedCheck,
  id: 812,
  source_run_id: 704,
  source_run_attempt: 1,
  event: 'workflow_dispatch',
  head_sha: monitorOldSha,
  source_run_display_title: 'Scale Small AI Release Health Monitor',
  started_at: '2026-07-18T09:01:00Z',
};
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    auditedLegacyMonitorFailedCheck,
    [auditedLegacyMonitorFailedCheck, currentIncidentMonitorCheck],
    799,
    2,
    monitorSearch,
  )?.id,
  899,
  'the exact audited legacy check may self-latch only through the exhaustive current incident job',
);
for (const mutation of [
  { id: 814 },
  { source_run_id: 706 },
  { source_run_attempt: 2 },
  { name: 'untrusted-job' },
  { app: { slug: 'external-provider' } },
]) {
  assert.equal(
    findProvisionalTrustedMonitorCheckRecovery(
      { ...auditedLegacyMonitorFailedCheck, ...mutation },
      [currentIncidentMonitorCheck],
      799,
      2,
      monitorSearch,
    ),
    null,
    'every immutable audited check identity field must match exactly',
  );
}
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    scheduledMonitorFailedCheck,
    [scheduledMonitorFailedCheck, currentIncidentMonitorCheck],
    799,
    2,
    monitorSearch,
  )?.id,
  899,
  'the exact current incident job may provisionally recover a scheduled monitor check',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    scheduledMonitorFailedCheck,
    [scheduledMonitorFailedCheck, { ...currentIncidentMonitorCheck, name: 'untrusted-job' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a different job must never recover the monitor check',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecovery(
    scheduledMonitorFailedCheck,
    [scheduledMonitorFailedCheck, currentIncidentMonitorCheck],
    799,
    1,
    monitorSearch,
  ),
  null,
  'a check from a prior run attempt must not self-latch the current attempt',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecoveryFromRun(
    scheduledMonitorFailedCheck,
    [scheduledMonitorFailure, currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  )?.id,
  799,
  'the exact current workflow run may bind recovery while GitHub has not indexed its check yet',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecoveryFromRun(
    incidentMonitorFailedCheck,
    [manualIncidentMonitorFailure, currentIncidentMonitorRun],
    799,
    2,
    monitorSearch,
  )?.id,
  799,
  'the exact current incident run may recover a shifted equal-width check before GitHub indexes its current job',
);
for (const origin of [incidentMonitorFailedCheck, repeatedIncidentMonitorFailedCheck]) {
  assert.equal(
    findProvisionalTrustedMonitorCheckRecoveryFromRun(
      origin,
      [manualIncidentMonitorFailure, repeatedIncidentMonitorFailure, currentIncidentMonitorRun],
      799,
      2,
      monitorSearch,
    )?.id,
    799,
    'repeated equal-width failed checks must not deadlock when only the current run is indexed',
  );
}
for (const origin of [incidentMonitorFailedCheck, chainedContinuousMonitorFailedCheck]) {
  assert.equal(
    findProvisionalTrustedMonitorCheckRecoveryFromRun(
      origin,
      [manualIncidentMonitorFailure, chainedContinuousMonitorFailure, currentIncidentMonitorRun],
      799,
      2,
      monitorSearch,
    )?.id,
    799,
    'the live incident-to-continuous failure chain must recover even before current check indexing',
  );
}
assert.equal(
  findProvisionalTrustedMonitorCheckRecoveryFromRun(
    incidentMonitorFailedCheck,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, status: 'completed', conclusion: 'failure' }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a completed current run must not provisionally recover a failed check',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecoveryFromRun(
    incidentMonitorFailedCheck,
    [manualIncidentMonitorFailure, currentIncidentMonitorRun],
    799,
    1,
    monitorSearch,
  ),
  null,
  'a prior current-run attempt must not provisionally recover a failed check',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecoveryFromRun(
    incidentMonitorFailedCheck,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, head_sha: monitorOldSha }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a non-current-main workflow run must not provisionally recover a failed check',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecoveryFromRun(
    incidentMonitorFailedCheck,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, head_sha: monitorEquivalentAncestorSha }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'an attested ancestor workflow must never impersonate the exact current provisional run',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecoveryFromRun(
    incidentMonitorFailedCheck,
    [manualIncidentMonitorFailure, { ...currentIncidentMonitorRun, head_repository: { full_name: 'untrusted/fork' } }],
    799,
    2,
    monitorSearch,
  ),
  null,
  'a workflow run from an unrelated repository stream must not provisionally recover a failed check',
);
assert.equal(
  findProvisionalTrustedMonitorCheckRecoveryFromRun(
    incidentMonitorFailedCheck,
    [manualIncidentMonitorFailure, currentScheduledMonitorRun],
    798,
    1,
    monitorSearch,
  ),
  null,
  'a narrower continuous run must not provisionally recover an incident check',
);
const currentManualContinuousMonitorCheck = {
  ...currentIncidentMonitorCheck,
  id: 898,
  source_run_id: 796,
  source_run_attempt: 1,
  source_run_display_title: 'Release health monitor [continuous:6h]',
  started_at: '2026-07-18T09:11:00Z',
};
const completedManualContinuousMonitorCheck = {
  ...currentManualContinuousMonitorCheck,
  id: 897,
  status: 'completed',
  conclusion: 'success',
  started_at: '2026-07-18T09:12:00Z',
};
assert.equal(
  findSupersedingCheck(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, completedManualContinuousMonitorCheck],
  )?.id,
  897,
  'the generic check selector demonstrates the same-trigger coverage bypass',
);
assert.equal(
  findPolicyBoundCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, completedManualContinuousMonitorCheck],
    monitorPolicy,
    monitorSearch,
  ),
  null,
  'the actual policy-bound check selector must reject narrower same-trigger recovery',
);
assert.equal(
  findPolicyBoundProvisionalCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, currentManualContinuousMonitorCheck],
    796,
    1,
    monitorPolicy,
    monitorSearch,
  ),
  null,
  'the actual policy-bound check self-latch must reject a narrower same-trigger scan',
);
const completedIncidentMonitorCheck = {
  ...currentIncidentMonitorCheck,
  id: 900,
  source_run_id: 800,
  source_run_attempt: 1,
  status: 'completed',
  conclusion: 'success',
  started_at: '2026-07-18T09:20:00Z',
};
assert.equal(
  findTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, completedIncidentMonitorCheck],
    monitorSearch,
  )?.id,
  900,
  'a successful exact source-verified incident job must durably recover an earlier equal-width incident check',
);
const ancestorIncidentMonitorFailedCheck = {
  ...incidentMonitorFailedCheck,
  id: 822,
  head_sha: monitorEquivalentAncestorSha,
};
const ancestorIncidentMonitorSuccessCheck = {
  ...completedIncidentMonitorCheck,
  id: 902,
  source_run_id: 802,
  head_sha: monitorEquivalentAncestorSha,
};
assert.equal(
  findTrustedMonitorCheckRecovery(
    ancestorIncidentMonitorFailedCheck,
    [ancestorIncidentMonitorFailedCheck, ancestorIncidentMonitorSuccessCheck],
    monitorSearch,
  )?.id,
  902,
  'an equivalent successful check at SHA A must durably recover after default main advances to SHA B',
);
const laterCurrentContinuousMonitorCheck = {
  ...currentManualContinuousMonitorCheck,
  id: 896,
  source_run_id: 794,
  event: 'schedule',
  started_at: '2026-07-18T09:30:00Z',
};
assert.equal(
  findPolicyBoundCheckRecovery(
    ancestorIncidentMonitorFailedCheck,
    [ancestorIncidentMonitorFailedCheck, ancestorIncidentMonitorSuccessCheck, laterCurrentContinuousMonitorCheck],
    monitorPolicy,
    monitorSearch,
  )?.id,
  902,
  'a scheduled six-hour check at SHA B must inherit the attested SHA A success instead of reopening the old check failure',
);
assert.equal(
  findTrustedMonitorCheckRecovery(
    ancestorIncidentMonitorFailedCheck,
    [ancestorIncidentMonitorFailedCheck, {
      ...ancestorIncidentMonitorSuccessCheck,
      id: 903,
      head_sha: monitorChangedAncestorSha,
    }],
    monitorSearch,
  ),
  null,
  'a changed-implementation ancestor check must not recover across SHAs',
);
assert.equal(
  findTrustedMonitorCheckRecovery(
    incidentMonitorFailedCheck,
    [incidentMonitorFailedCheck, {
      ...completedIncidentMonitorCheck,
      id: 901,
      source_run_id: 801,
      source_run_display_title: 'Release health monitor [incident:167h]',
      started_at: '2026-07-18T09:21:00Z',
    }],
    monitorSearch,
  ),
  null,
  'a successful but narrower incident job must not durably recover a broader incident check failure',
);
assert.equal(
  findTrustedMonitorCheckRecovery(
    { ...incidentMonitorFailedCheck, app: { slug: 'external-provider' } },
    [completedIncidentMonitorCheck],
    monitorSearch,
  ),
  null,
  'an external provider failure must remain outside trusted monitor recovery',
);
assert.equal(
  deploymentJobStreamIdentity({ ...failedCheck, event: 'push', head_repository: 'ScaleSmall/SSAI_RR' }),
  deploymentJobStreamIdentity({ ...failedCheck, event: 'workflow_dispatch', head_repository: 'ScaleSmall/SSAI_RR' }),
  'a later proven deployment of the same workflow job may recover a failed deployment across trigger types',
);
assert.notEqual(
  deploymentJobStreamIdentity({ ...failedCheck, name: 'deploy (crm-to-queue)', head_repository: 'ScaleSmall/SSAI_RR' }),
  deploymentJobStreamIdentity({ ...failedCheck, name: 'deploy (rr-referral)', head_repository: 'ScaleSmall/SSAI_RR' }),
  'different deployment jobs must never recover one another',
);
const checkRecovery = findSupersedingCheck(failedCheck, [
  failedCheck,
  { ...failedCheck, id: 502, conclusion: 'success', workflow_id: 200, started_at: '2026-07-18T09:02:00Z' },
  { ...failedCheck, id: 503, conclusion: 'success', event: 'workflow_dispatch', started_at: '2026-07-18T09:03:00Z' },
  { ...failedCheck, id: 504, conclusion: 'success', started_at: '2026-07-18T09:04:00Z' },
]);
assert.equal(checkRecovery?.id, 504, 'GitHub Actions check recovery must require workflow, event, branch, provider, and job name');
const manualDeploymentCheck = {
  ...failedCheck,
  id: 506,
  event: 'workflow_dispatch',
  name: 'deploy (crm-to-queue)',
  status: 'completed',
  conclusion: 'success',
  started_at: '2026-07-18T09:05:00Z',
  head_repository: 'ScaleSmall/SSAI_RR',
};
const failedDeploymentCheck = {
  ...failedCheck,
  name: 'deploy (crm-to-queue)',
  head_repository: 'ScaleSmall/SSAI_RR',
};
const provenDeploymentRecovery = findDeploymentCheckRecovery(
  failedDeploymentCheck,
  [{
    id: 899,
    state: 'failure',
    stream_identity: 'deployment:production:crm-to-queue',
    deployment_job_identity: deploymentJobStreamIdentity(failedDeploymentCheck),
    source_check_run_id: failedDeploymentCheck.id,
    created_at: '2026-07-18T09:01:00Z',
  }, {
    id: 900,
    state: 'success',
    stream_identity: 'deployment:production:crm-to-queue',
    deployment_job_identity: deploymentJobStreamIdentity(manualDeploymentCheck),
    source_check_run_id: manualDeploymentCheck.id,
    created_at: '2026-07-18T09:06:00Z',
  }, {
    id: 901,
    state: 'success',
    stream_identity: 'deployment:staging:crm-to-queue',
    deployment_job_identity: deploymentJobStreamIdentity(manualDeploymentCheck),
    source_check_run_id: manualDeploymentCheck.id,
    created_at: '2026-07-18T09:07:00Z',
  }],
  [failedDeploymentCheck, manualDeploymentCheck],
);
assert.equal(provenDeploymentRecovery?.check.id, 506, 'a check may recover across trigger types only when a later matching deployment succeeded');
assert.equal(provenDeploymentRecovery?.status.id, 900, 'a successful deployment in another environment must not recover the failed environment');
assert.equal(findDeploymentCheckRecovery(failedDeploymentCheck, [], [manualDeploymentCheck]), null, 'a manual success without deployment evidence must not suppress a push failure');

const cloudflareFailure = {
  id: 700,
  name: 'Cloudflare Pages',
  app: { slug: 'cloudflare-workers-and-pages' },
  head_branch: 'feature',
  head_repository: 'ScaleSmall/SSAI_Dashboard',
  head_sha: 'c'.repeat(40),
  pull_numbers: [15],
  status: 'completed',
  conclusion: 'failure',
  started_at: '2026-07-18T09:00:00Z',
};
const mergedPullCheck = {
  ...cloudflareFailure,
  id: 701,
  head_branch: 'main',
  head_sha: 'd'.repeat(40),
  pull_numbers: [15],
  conclusion: 'success',
  started_at: '2026-07-18T09:06:00Z',
};
const pullByNumber = new Map([[15, {
  number: 15,
  merged_at: '2026-07-18T09:05:00Z',
  merge_commit_sha: 'd'.repeat(40),
}]]);

const failedWorkflowStartup = {
  id: 697,
  workflow_id: 303959338,
  name: '.github/workflows/ci.yml',
  event: 'push',
  head_branch: 'codex/harden-synthetic-dispatch-admission-20260720',
  head_repository: { full_name: 'ScaleSmall/SSAI_Database' },
  head_sha: 'a'.repeat(40),
  status: 'completed',
  conclusion: 'failure',
  run_started_at: '2026-07-18T09:00:00Z',
  pull_requests: [],
};
const mergedWorkflowSuccess = {
  ...failedWorkflowStartup,
  id: 698,
  name: 'CI',
  head_branch: 'main',
  head_repository: { full_name: 'ScaleSmall/SSAI_Database' },
  head_sha: 'd'.repeat(40),
  conclusion: 'success',
  run_started_at: '2026-07-18T09:06:00Z',
};
const workflowPullByNumber = new Map([[15, {
  number: 15,
  merged_at: '2026-07-18T09:05:00Z',
  merge_commit_sha: 'd'.repeat(40),
  head: {
    ref: 'codex/harden-synthetic-dispatch-admission-20260720',
    repo: { full_name: 'ScaleSmall/SSAI_Database' },
  },
  base: { repo: { full_name: 'ScaleSmall/SSAI_Database' } },
}]]);
const associatedWorkflowRuns = associateWorkflowRunsWithPulls(
  [failedWorkflowStartup, mergedWorkflowSuccess],
  [{
    sha: 'a'.repeat(40),
    _pull_number: 15,
    _branch: 'codex/harden-synthetic-dispatch-admission-20260720',
    _head_repository: 'ScaleSmall/SSAI_Database',
  }],
);
assert.deepEqual(associatedWorkflowRuns[0].pull_numbers, [15], 'an exact pull commit may restore a startup-failed run\'s missing pull association');
assert.deepEqual(
  associateWorkflowRunsWithPulls([failedWorkflowStartup], [{
    sha: 'a'.repeat(40),
    _pull_number: 16,
    _branch: 'another-branch',
    _head_repository: 'ScaleSmall/SSAI_Database',
  }, {
    sha: 'a'.repeat(40),
    _pull_number: 17,
    _branch: failedWorkflowStartup.head_branch,
    _head_repository: 'untrusted/fork',
  }])[0].pull_numbers,
  [],
  'a same-SHA branch or repository mismatch must not create a pull association',
);
assert.equal(
  findMergedPullWorkflowRecovery(
    associatedWorkflowRuns[0],
    associatedWorkflowRuns,
    workflowPullByNumber,
    'main',
    new Set(['d'.repeat(40)]),
  )?.run.id,
  698,
  'a failed branch workflow may recover only through the exact merged pull and exact successful merge-commit push',
);
for (const [label, failedMutation, successMutation, pullMutation] of [
  ['ambiguous pull identity', { pull_numbers: [15, 16] }, {}, {}],
  ['missing workflow identity', { workflow_id: null }, {}, {}],
  ['manual failed origin', { event: 'workflow_dispatch' }, {}, {}],
  ['default-branch failed origin', { head_branch: 'main' }, {}, {}],
  ['wrong workflow', {}, { workflow_id: 999 }, {}],
  ['manual merge-commit run', {}, { event: 'workflow_dispatch' }, {}],
  ['wrong recovery branch', {}, { head_branch: 'release' }, {}],
  ['wrong recovery repository', {}, { head_repository: { full_name: 'another/repo' } }, {}],
  ['recovery predates merge', {}, { run_started_at: '2026-07-18T09:04:00Z' }, {}],
  ['wrong merge SHA', {}, {}, { merge_commit_sha: 'e'.repeat(40) }],
  ['wrong pull branch', {}, {}, { head: { ref: 'another-branch', repo: { full_name: 'ScaleSmall/SSAI_Database' } } }],
  ['wrong pull repository', {}, {}, { head: { ref: failedWorkflowStartup.head_branch, repo: { full_name: 'untrusted/fork' } } }],
  ['wrong base repository', {}, {}, { base: { repo: { full_name: 'another/repo' } } }],
  ['merge predates failure', {}, {}, { merged_at: '2026-07-18T08:59:00Z' }],
  ['unsuccessful merge run', {}, { conclusion: 'failure' }, {}],
]) {
  const failedCandidate = { ...associatedWorkflowRuns[0], ...failedMutation };
  const successCandidate = { ...associatedWorkflowRuns[1], ...successMutation };
  const pullCandidate = { ...workflowPullByNumber.get(15), ...pullMutation };
  assert.equal(
    findMergedPullWorkflowRecovery(
      failedCandidate,
      [failedCandidate, successCandidate],
      new Map([[15, pullCandidate]]),
      'main',
      new Set(['d'.repeat(40)]),
    ),
    null,
    label + ' must fail closed',
  );
}
assert.equal(
  findMergedPullWorkflowRecovery(
    associatedWorkflowRuns[0],
    associatedWorkflowRuns,
    workflowPullByNumber,
    'main',
    new Set(),
  ),
  null,
  'a merge commit removed from current default-branch history must not recover a branch failure',
);
assert.equal(
  findMergedPullCheckRecovery(cloudflareFailure, [cloudflareFailure, mergedPullCheck], pullByNumber, 'main')?.check.id,
  701,
  'a failed preview may recover only on the exact merged pull-request commit',
);
assert.equal(
  findMergedPullCheckRecovery(cloudflareFailure, [cloudflareFailure, { ...mergedPullCheck, head_sha: 'e'.repeat(40) }], pullByNumber, 'main'),
  null,
  'an unrelated successful default-branch commit must not suppress a preview failure',
);
const associatedChecks = associateChecksWithPulls([{
  ...cloudflareFailure,
  pull_numbers: [],
}], [{
  number: 15,
  head: { ref: 'feature', repo: { full_name: 'ScaleSmall/SSAI_Dashboard' } },
}, {
  number: 16,
  head: { ref: 'feature', repo: { full_name: 'another/repo' } },
}]);
assert.deepEqual(associatedChecks[0].pull_numbers, [15], 'force-pushed commits must recover their pull identity only by exact head repository and branch');
assert.equal(findSupersedingCheck({ ...failedCheck, id: 505, started_at: '2026-07-18T10:00:00Z' }, [failedCheck]), null);
assert.notEqual(
  checkStreamIdentity({ ...failedCheck, workflow_id: 100 }),
  checkStreamIdentity({ ...failedCheck, workflow_id: 200 }),
  'same-named jobs in different workflows must not share a recovery stream',
);
assert.notEqual(
  checkStreamIdentity({ ...failedCheck, head_repository: 'customer-a/repo', head_branch: 'feature' }),
  checkStreamIdentity({ ...failedCheck, head_repository: 'customer-b/repo', head_branch: 'feature' }),
  'same-named fork branches must never recover one another',
);
assert.notEqual(
  workflowStreamIdentity({ ...failedRun, head_repository: { full_name: 'customer-a/repo' } }),
  workflowStreamIdentity({ ...failedRun, head_repository: { full_name: 'customer-b/repo' } }),
  'workflow recovery must preserve fork repository identity',
);
assert.notEqual(
  checkStreamIdentity({ ...failedCheck, app: { slug: 'cloudflare-workers-and-pages' }, workflow_id: null, event: '', head_branch: '', head_sha: 'c'.repeat(40) }),
  checkStreamIdentity({ ...failedCheck, app: { slug: 'cloudflare-workers-and-pages' }, workflow_id: null, event: '', head_branch: '', head_sha: 'd'.repeat(40) }),
  'external checks with ambiguous branches must fail closed to their exact SHA',
);

const currentCheck = { ...failedCheck, id: 599, source_run_id: 999, source_run_attempt: 2, status: 'in_progress', conclusion: null, started_at: '2026-07-18T09:10:00Z' };
assert.equal(
  findProvisionalCheckRecovery(failedCheck, [failedCheck, currentCheck], 999, 2)?.id,
  599,
  'the in-progress monitor check must provisionally clear its own previous failure',
);
assert.equal(findProvisionalCheckRecovery(failedCheck, [failedCheck, currentCheck], 998, 2), null);
assert.equal(findProvisionalCheckRecovery(failedCheck, [failedCheck, currentCheck], 999, 1), null, 'a prior run attempt must not self-latch the current attempt');

const failedStatus = {
  id: 601,
  context: 'Cloudflare Pages',
  head_branch: 'main',
  sha: 'e'.repeat(40),
  state: 'failure',
  created_at: '2026-07-18T09:00:00Z',
};
const statusRecovery = findSupersedingCommitStatus(failedStatus, [
  failedStatus,
  { ...failedStatus, id: 602, state: 'success', head_branch: 'feature', created_at: '2026-07-18T09:02:00Z' },
  { ...failedStatus, id: 603, state: 'success', created_at: '2026-07-18T09:03:00Z' },
]);
assert.equal(statusRecovery?.id, 603, 'classic commit-status recovery must preserve branch and context');
assert.notEqual(
  commitStatusStreamIdentity({ ...failedStatus, head_branch: '', sha: 'e'.repeat(40) }),
  commitStatusStreamIdentity({ ...failedStatus, head_branch: '', sha: 'f'.repeat(40) }),
  'ambiguous commit statuses must fail closed to their exact SHA',
);
assert.notEqual(
  commitStatusStreamIdentity({ ...failedStatus, head_repository: 'customer-a/repo', head_branch: 'feature' }),
  commitStatusStreamIdentity({ ...failedStatus, head_repository: 'customer-b/repo', head_branch: 'feature' }),
  'classic statuses on same-named fork branches must not share a recovery stream',
);

assert.equal(
  recordActivityTime({ created_at: '2026-07-17T09:00:00Z', updated_at: '2026-07-18T09:00:00Z' }),
  Date.parse('2026-07-18T09:00:00Z'),
  'lookback selection must honor recent updates to older records',
);

console.log('Release-health recovery identities and adversarial selection verified.');
