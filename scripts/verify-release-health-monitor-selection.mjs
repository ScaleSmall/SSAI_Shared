import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  associateChecksWithPulls,
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
  findSupersedingCheck,
  findSupersedingCommitStatus,
  findSupersedingDeployment,
  findSupersedingWorkflowRun,
  findTrustedMonitorCheckRecovery,
  findTrustedMonitorWorkflowRecovery,
  isTrustedMonitorRecoveryPolicy,
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
};
const monitorPolicy = verifyForwardFixRecoveryPolicy({
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: monitorPolicyInput,
});
assert.ok(monitorPolicy, 'trusted monitor recovery requires an exact source-hashed policy');
assert.equal(isTrustedMonitorRecoveryPolicy(monitorPolicy), true, 'the exact monitor policy must enter trusted monitor recovery');
assert.equal(verifyForwardFixRecoveryPolicy({
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: { ...monitorPolicyInput, monitorSelfRecoveryEvents: [] },
}), null, 'an empty trusted monitor event set must fail closed');

const monitorOldSha = '3'.repeat(40);
const monitorCurrentSha = '4'.repeat(40);
const monitorSearch = {
  policy: monitorPolicy,
  currentHeadSha: monitorCurrentSha,
  defaultBranch: 'main',
  defaultCommitShas: new Set([monitorOldSha, monitorCurrentSha]),
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
  'an exact current scheduled scan may self-latch an older dispatch failure with equal coverage',
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
const completedIncidentMonitorRun = {
  ...currentIncidentMonitorRun,
  id: 800,
  run_attempt: 1,
  status: 'completed',
  conclusion: 'success',
  created_at: '2026-07-18T09:20:00Z',
};
assert.equal(
  findTrustedMonitorWorkflowRecovery(
    manualIncidentMonitorFailure,
    [manualIncidentMonitorFailure, completedIncidentMonitorRun],
    monitorSearch,
  )?.id,
  800,
  'a completed incident scan may recover a prior same-SHA incident failure',
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
  'a completed exact monitor job may recover a prior cross-trigger check',
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
