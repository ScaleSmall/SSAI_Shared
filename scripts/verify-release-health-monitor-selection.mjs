import assert from 'node:assert/strict';
import {
  associateChecksWithPulls,
  checkStreamIdentity,
  commitStatusStreamIdentity,
  deploymentJobStreamIdentity,
  deploymentStreamIdentity,
  findProvisionalCheckRecovery,
  findProvisionalWorkflowRecovery,
  findDeploymentCheckRecovery,
  findMergedPullCheckRecovery,
  findSupersedingCheck,
  findSupersedingCommitStatus,
  findSupersedingDeployment,
  findSupersedingWorkflowRun,
  latestByIdentity,
  recordActivityTime,
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

const currentRun = { ...failedRun, id: 999, run_attempt: 2, status: 'in_progress', conclusion: null, created_at: '2026-07-18T09:10:00Z' };
assert.equal(
  findProvisionalWorkflowRecovery(failedRun, [failedRun, currentRun], 999, 2)?.id,
  999,
  'the in-progress monitor run must provisionally clear its own previous failure so it can become the recovery',
);
assert.equal(findProvisionalWorkflowRecovery(failedRun, [failedRun, currentRun], 998, 2), null, 'an unrelated run must not suppress a failure');

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

const currentCheck = { ...failedCheck, id: 599, source_run_id: 999, status: 'in_progress', conclusion: null, started_at: '2026-07-18T09:10:00Z' };
assert.equal(
  findProvisionalCheckRecovery(failedCheck, [failedCheck, currentCheck], 999)?.id,
  599,
  'the in-progress monitor check must provisionally clear its own previous failure',
);
assert.equal(findProvisionalCheckRecovery(failedCheck, [failedCheck, currentCheck], 998), null);

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
