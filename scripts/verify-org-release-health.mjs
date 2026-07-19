import { appendFile } from 'node:fs/promises';
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
  findDeploymentCheckRecovery,
  findMergedPullCheckRecovery,
  findSupersedingCommitStatus,
  findSupersedingDeployment,
  findTrustedMonitorCheckRecovery,
  isTrustedMonitorRecoveryPolicy,
  latestByIdentity,
  partitionWorkflowHealth,
  rateHeadroomDecision,
  recordActivityTime,
  recordOccurrenceTime,
  verifyForwardFixRecoveryPolicy,
  workflowStreamIdentity,
} from './release-health-monitor-utils.mjs';

const token = requiredSecret(process.env.SSAI_RELEASE_MONITOR_GITHUB_TOKEN, 'SSAI_RELEASE_MONITOR_GITHUB_TOKEN');
const owner = safeName(process.env.SSAI_RELEASE_MONITOR_OWNER || 'ScaleSmall', 'SSAI_RELEASE_MONITOR_OWNER');
const repoPrefix = safeName(process.env.SSAI_RELEASE_MONITOR_REPO_PREFIX || 'SSAI_', 'SSAI_RELEASE_MONITOR_REPO_PREFIX');
const excludedRepositories = new Set(['SSAI_Connect']);
const scanMode = enumValue(process.env.SSAI_RELEASE_MONITOR_MODE || 'continuous', ['continuous', 'incident'], 'SSAI_RELEASE_MONITOR_MODE');
const stuckMinutes = boundedNumber(process.env.SSAI_RELEASE_MONITOR_STUCK_MINUTES, 45, 15, 240);
const requestedLookbackHours = boundedNumber(process.env.SSAI_RELEASE_MONITOR_LOOKBACK_HOURS, 6, 1, 168);
if (scanMode === 'continuous' && requestedLookbackHours > 6) {
  throw new Error('Continuous monitoring is limited to 6 hours. Use incident mode for an exhaustive 7-day sweep.');
}
const lookbackHours = requestedLookbackHours;
const maxRequests = boundedInteger(
  process.env.SSAI_RELEASE_MONITOR_MAX_REQUESTS,
  scanMode === 'incident' ? 3500 : 600,
  100,
  scanMode === 'incident' ? 4500 : 750,
);
const rateReserve = boundedInteger(
  process.env.SSAI_RELEASE_MONITOR_RATE_RESERVE,
  scanMode === 'incident' ? 250 : 1000,
  100,
  2000,
);
const apiConcurrency = boundedInteger(process.env.SSAI_RELEASE_MONITOR_API_CONCURRENCY, 6, 1, 10);
const nowMs = Date.now();
const stuckMs = stuckMinutes * 60_000;
const cutoffMs = nowMs - (lookbackHours * 60 * 60_000);
const cutoffIso = new Date(cutoffMs).toISOString();
const rerunOriginHours = scanMode === 'incident' ? lookbackHours : 168;
const rerunOriginCutoffMs = nowMs - (rerunOriginHours * 60 * 60_000);
const deploymentOriginHours = scanMode === 'incident' ? lookbackHours : 168;
const deploymentOriginCutoffMs = nowMs - (deploymentOriginHours * 60 * 60_000);
const currentRepository = String(process.env.GITHUB_REPOSITORY || '');
const currentRepoName = currentRepository.startsWith(owner + '/') ? currentRepository.slice(owner.length + 1) : '';
const currentRunId = numericIdentifier(process.env.GITHUB_RUN_ID);
const currentRunAttempt = numericIdentifier(process.env.GITHUB_RUN_ATTEMPT) || 1;
const pageLimits = scanMode === 'incident'
  ? { workflows: 10, runs: 50, commits: 20, pulls: 10, branches: 10, checks: 20, statuses: 20, deployments: 50, repositories: 10 }
  : { workflows: 10, runs: 10, commits: 5, pulls: 3, branches: 3, checks: 5, statuses: 5, deployments: 10, repositories: 10 };

const noHistoryPolicies = new Map([
  ['SSAI_CI_Engine:Retire Production CI Test Token Broker', {
    path: '.github/workflows/retire-production-ci-test-tokens.yml',
    sourceSha256: '3cd089034a5b52f8ddd0297f1d82d8fc4422bccb7a1aac00e9c7750875f023a5',
    reason: 'One-shot manual broker-retirement control remains dormant until permanent production test-token retirement is authorized.',
    witness: {
      name: 'Production Customer Intelligence Worker',
      path: '.github/workflows/production-ci-worker.yml',
      headRepository: 'ScaleSmall/SSAI_CI_Engine',
      allowedEvents: ['schedule', 'workflow_dispatch'],
      maxAgeHours: 4,
    },
  }],
  ['SSAI_Analytics_Reporting:Deploy Production Analytics Pages', {
    path: '.github/workflows/deploy-production-pages.yml',
    sourceSha256: '1ffee267b32c9a5579455fc8b4684ab28c7be0d187a7f0a50257ce6ad1299cc6',
    reason: 'Manual-only production release control is dormant; live Analytics Pages health must instead be proven by its scheduled canary.',
    witness: {
      name: 'Production Analytics Pages Canary',
      path: '.github/workflows/production-pages-canary.yml',
      headRepository: 'ScaleSmall/SSAI_Analytics_Reporting',
      allowedEvents: ['schedule', 'workflow_dispatch'],
      maxAgeHours: 30,
    },
  }],
]);
const legacyMonitorTitle = 'Scale Small AI Release Health Monitor';
const legacySnapshotWorkflowSourceSha256 = '0faccc93dd783cd0c76ecd837bcd5bb6cbb046b2670a0f7f41d039e433c49b04';
const legacyBoundedWorkflowSourceSha256 = '1adbb7b1738f9562968a644b8854bf7fc04496eea976809cae83429204f14858';
const currentMonitorWorkflowSourceSha256 = '3672ed17290279e20d75336e810d9327a59786c16a77332aa5be2f4adb0238a1';
const auditedMonitorSourceEvidence = new Map([
  ['82fc98124d0b5412e3591c9357da76ba7f324737', {
    workflowSourceSha256: legacySnapshotWorkflowSourceSha256,
    scriptSourceSha256: '1f4b7d0700abd526c1da9f6f048c4ffc1b943cac51a9811ab47f486339bf5233',
    utilsSourceSha256: null,
  }],
  ['826e4bd44784dc06d507cef6df0b0bd4c27ce51b', {
    workflowSourceSha256: legacyBoundedWorkflowSourceSha256,
    scriptSourceSha256: 'ab2f0cb331e4abbdb265e3f4bf2d55bd8498a142945a88f035eb3d799ad729a8',
    utilsSourceSha256: 'a1134fd75c7218cbd0bd60fbbb62f1f385f003caafddefb1637b66d7fefcb306',
  }],
  ['7c5761cb101c93de492b55fb544af14d747076d3', {
    workflowSourceSha256: legacyBoundedWorkflowSourceSha256,
    scriptSourceSha256: 'e066575bd20137a09928a1e5bedc68083f57611480f58c3d9d50320269272b6b',
    utilsSourceSha256: '912fb227ef10a03fb45643fb1b337f9827423179ca3d39959f8ac1ffe9cd5a78',
  }],
  ['2ee88f7cca1468f35695d08fff629b7400869a78', {
    workflowSourceSha256: legacyBoundedWorkflowSourceSha256,
    scriptSourceSha256: 'fd87d5f0413ac7e15542c649c83e3d156a168d6a9c3d1da69548b771152fa6bd',
    utilsSourceSha256: 'dc33eab5f1182ae2244b3934aa013f41e099294dac2fab1307e63a40a6e45b48',
  }],
  ['256eddb68de8c5f4d52e1b424631e3beef1387ae', {
    workflowSourceSha256: currentMonitorWorkflowSourceSha256,
    scriptSourceSha256: '81fa74492549661e9af45220471ba9392bcc3e44c2cbbd43ea415fa53a3861ae',
    utilsSourceSha256: 'c44b19a4849593680c992dad8ae85a37bc87b899e7a66312045ff17b09d1cfd6',
  }],
  ['5a4ece6019c44c585f4f67b2bc3a7c50bc55f61d', {
    workflowSourceSha256: currentMonitorWorkflowSourceSha256,
    scriptSourceSha256: '7a783131a8eaac171b4f4e70ecbe84945db44d16217e08976c0f4f5af8906b6d',
    utilsSourceSha256: 'ad0b6b22c6b19cbfa8752130928b982f0bf8bbfe35c70430c2a739f5256ac4b6',
  }],
]);
const auditedMonitorOrigin = (
  runId,
  runAttempt,
  checkRunId,
  headSha,
  event,
  displayTitle,
  coverageMode,
  coverageHours,
  workflowSourceSha256,
  coverageStartedAt,
) => {
  const sourceEvidence = auditedMonitorSourceEvidence.get(headSha);
  if (!sourceEvidence || sourceEvidence.workflowSourceSha256 !== workflowSourceSha256) {
    throw new Error('Audited monitor source evidence is missing or inconsistent for ' + headSha + '.');
  }
  return {
    runId,
    runAttempt,
    checkRunId,
    headSha,
    event,
    displayTitle,
    coverageMode,
    coverageHours,
    ...sourceEvidence,
    ...(coverageStartedAt ? { coverageStartedAt } : {}),
  };
};
const forwardFixRecoveryPolicies = new Map([
  ['SSAI_PoW:315750527', {
    workflowId: 315750527,
    path: '.github/workflows/n8n-production-exactness.yml',
    sourceSha256: 'e9a9baf81da16082915e555acfac678865f9a0cc82cde65fcac984cfb6a4b7a2',
    headRepository: 'ScaleSmall/SSAI_PoW',
    failedEvents: ['schedule'],
    recoveryEvents: ['workflow_dispatch'],
    jobNames: ['verify-production'],
    recoveryDisplayTitles: ['Production n8n workflow exactness'],
  }],
  ['SSAI_Shared:315630665', {
    workflowId: 315630665,
    path: '.github/workflows/release-health-monitor.yml',
    sourceSha256: '3672ed17290279e20d75336e810d9327a59786c16a77332aa5be2f4adb0238a1',
    headRepository: 'ScaleSmall/SSAI_Shared',
    failedEvents: ['schedule'],
    recoveryEvents: ['workflow_dispatch'],
    jobNames: ['Verify current organization release health'],
    recoveryDisplayTitles: ['Release health monitor [continuous:6h]'],
    monitorSelfRecoveryContract: 'release-health-monitor-v1',
    monitorSelfRecoveryEvents: ['schedule', 'workflow_dispatch'],
    // Exact, immutable attempts whose pre-run-name coverage and failure
    // predicates were reconstructed from GitHub metadata, logs, and the source
    // at each default-branch commit. No unlisted generic title is trusted.
    auditedMonitorOrigins: [
      auditedMonitorOrigin(29638546298, 1, 88065007292, '82fc98124d0b5412e3591c9357da76ba7f324737', 'workflow_dispatch', legacyMonitorTitle, 'incident', 168, legacySnapshotWorkflowSourceSha256, '2026-07-18T09:04:30Z'),
      auditedMonitorOrigin(29638605524, 1, 88065154975, '82fc98124d0b5412e3591c9357da76ba7f324737', 'workflow_dispatch', legacyMonitorTitle, 'incident', 168, legacySnapshotWorkflowSourceSha256, '2026-07-18T09:04:30Z'),
      auditedMonitorOrigin(29646585368, 1, 88085761786, '826e4bd44784dc06d507cef6df0b0bd4c27ce51b', 'workflow_dispatch', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29647911322, 1, 88089143117, '7c5761cb101c93de492b55fb544af14d747076d3', 'workflow_dispatch', legacyMonitorTitle, 'incident', 168, legacyBoundedWorkflowSourceSha256, '2026-07-18T13:47:31Z'),
      auditedMonitorOrigin(29649650403, 1, 88093662012, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29654185740, 1, 88105503984, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29656236744, 1, 88111016982, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29658639760, 1, 88117312495, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29660632726, 1, 88122577706, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29662513423, 1, 88127459946, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29664360347, 1, 88132200888, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29666205608, 1, 88136933929, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29672532340, 1, 88154008729, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29676775338, 1, 88165488989, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29680730786, 1, 88176313324, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29683741127, 1, 88184372919, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29685649354, 1, 88189329304, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29687398415, 1, 88194018679, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29690404816, 1, 88201983366, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29692821939, 1, 88208443973, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29694906744, 1, 88213880181, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29697092554, 1, 88219602143, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29698681710, 1, 88223813796, '2ee88f7cca1468f35695d08fff629b7400869a78', 'workflow_dispatch', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      auditedMonitorOrigin(29699095663, 1, 88224952994, '2ee88f7cca1468f35695d08fff629b7400869a78', 'schedule', legacyMonitorTitle, 'continuous', 6, legacyBoundedWorkflowSourceSha256),
      // The first source-verified incident run was complete and had no current
      // production, no-history, status, or deployment red. Its only unresolved
      // records were the exact 24 attempts above, so the next incident scan may
      // recover it only if its window still includes their earliest predicate.
      auditedMonitorOrigin(29704911896, 1, 88240157445, '256eddb68de8c5f4d52e1b424631e3beef1387ae', 'workflow_dispatch', 'Release health monitor [incident:168h]', 'incident', 168, currentMonitorWorkflowSourceSha256, '2026-07-18T09:04:30Z'),
      // This exact incident stopped at the fail-closed API headroom gate before
      // inventory: 2474 remained, 3750 was required, reset 22:27:02Z. A later
      // incident may recover it only by completing the exhaustive scan.
      auditedMonitorOrigin(29705959736, 1, 88242895212, '5a4ece6019c44c585f4f67b2bc3a7c50bc55f61d', 'workflow_dispatch', 'Release health monitor [incident:168h]', 'incident', 168, currentMonitorWorkflowSourceSha256, '2026-07-19T22:20:08Z'),
    ],
  }],
]);
const acceptableConclusions = new Set(['success', 'neutral', 'skipped']);
const failedConclusions = new Set(['failure', 'cancelled', 'timed_out', 'action_required', 'startup_failure', 'stale']);
const failedDeploymentStates = new Set(['failure', 'error']);
const pendingDeploymentStates = new Set(['queued', 'pending', 'in_progress']);
const failures = [];
const warnings = [];
const rows = [];
const recoveryEvidence = { workflows: [], checks: [], statuses: [], deployments: [] };
const provisionalEvidence = { workflows: [], checks: [] };
const unresolvedEvidence = { workflows: [], checks: [], statuses: [], deployments: [] };
const requestStats = { requests: 0, retries: 0, rate_remaining: null, rate_reset_at: null };
const apiGate = createConcurrencyGate(apiConcurrency);

// GitHub's /rate_limit endpoint can be served from a different cache/rate
// context than repository APIs. Probe an authenticated core endpoint so the
// preflight uses the same quota bucket the inventory will actually consume.
await api('/user');
if (!Number.isSafeInteger(requestStats.rate_remaining)) {
  throw new Error('GitHub API rate-limit headers were unavailable. The scan cannot prove sufficient request headroom and is failing closed.');
}
const rateDecision = rateHeadroomDecision(scanMode, requestStats.rate_remaining, rateReserve, maxRequests);
if (rateDecision === 'fail') {
  throw new Error('Incident scan requires at least ' + (rateReserve + maxRequests)
    + ' GitHub API requests of starting headroom, but only ' + requestStats.rate_remaining
    + ' remain. Retry after the rate limit resets at ' + (requestStats.rate_reset_at || 'the provider reset time') + '.');
}
if (rateDecision === 'defer') {
  const deferredSummary = deferredRateSummary();
  console.log(JSON.stringify(deferredSummary, null, 2));
  console.error('::warning::Continuous release-health scan deferred until GitHub API quota resets; no inventory was sampled or reported as healthy.');
  await writeStepSummary(deferredSummary);
} else {
  const repositories = (await listRepositories())
  .filter((repo) => repo.owner?.login === owner
    && !repo.archived
    && String(repo.name).startsWith(repoPrefix)
    && !excludedRepositories.has(String(repo.name)))
  .sort((left, right) => left.name.localeCompare(right.name));

if (repositories.length === 0) {
  throw new Error('No active ' + owner + '/' + repoPrefix + '* repositories were visible to the monitor token.');
}

await mapLimit(repositories, 4, inspectRepository);

if (requestStats.requests > Math.floor(maxRequests * 0.8)) {
  warnings.push('GitHub API use exceeded 80% of the configured per-run request budget.');
}
if (requestStats.rate_remaining !== null && requestStats.rate_remaining < rateReserve + 250) {
  warnings.push('GitHub API rate-limit headroom finished close to the configured reserve.');
}

const workflowRows = rows.flatMap((row) => row.workflows);
const {
  green: greenWorkflows,
  pending: pendingWorkflows,
  failed: failedWorkflows,
  allowedNoHistory: allowedNoHistoryWorkflows,
  unresolvedNoHistory: unresolvedNoHistoryWorkflows,
  categorized: categorizedWorkflows,
} = partitionWorkflowHealth(workflowRows, acceptableConclusions);
const summary = {
  ok: failures.length === 0,
  deferred: false,
  inventory_complete: true,
  checked_at: new Date().toISOString(),
  owner,
  repository_prefix: repoPrefix,
  scan_mode: scanMode,
  repositories: repositories.length,
  active_workflows: workflowRows.length,
  green_workflows: greenWorkflows.length,
  pending_workflows: pendingWorkflows.length,
  failed_workflows: failedWorkflows.length,
  allowed_no_history_workflows: allowedNoHistoryWorkflows.length,
  unresolved_no_history_workflows: unresolvedNoHistoryWorkflows.length,
  categorized_workflows: categorizedWorkflows,
  workflow_categories_complete: categorizedWorkflows === workflowRows.length,
  allowed_no_history_evidence: allowedNoHistoryWorkflows.map((row) => ({
    repo: row.repo,
    workflow: row.name,
    reason: row.no_history_reason,
    workflow_source_sha256: row.no_history_source_sha256,
    witness: row.no_history_witness,
  })),
  current_commit_checks: rows.reduce((total, row) => total + row.checks.length + row.statuses.length, 0),
  lookback_hours: lookbackHours,
  lookback_started_at: cutoffIso,
  rerun_origin_hours: rerunOriginHours,
  deployment_origin_hours: deploymentOriginHours,
  recent_unsuccessful_workflow_attempts: recoveryEvidence.workflows.length + provisionalEvidence.workflows.length + unresolvedEvidence.workflows.length,
  recovered_recent_workflow_attempts: recoveryEvidence.workflows.length,
  provisional_self_recovering_workflow_attempts: provisionalEvidence.workflows.length,
  unresolved_recent_workflow_attempts: unresolvedEvidence.workflows.length,
  recent_failed_check_runs: recoveryEvidence.checks.length + provisionalEvidence.checks.length + unresolvedEvidence.checks.length,
  recovered_recent_check_runs: recoveryEvidence.checks.length,
  provisional_self_recovering_check_runs: provisionalEvidence.checks.length,
  unresolved_recent_check_runs: unresolvedEvidence.checks.length,
  recent_failed_commit_statuses: recoveryEvidence.statuses.length + unresolvedEvidence.statuses.length,
  recovered_recent_commit_statuses: recoveryEvidence.statuses.length,
  unresolved_recent_commit_statuses: unresolvedEvidence.statuses.length,
  recent_failed_deployment_statuses: recoveryEvidence.deployments.length + unresolvedEvidence.deployments.length,
  recovered_recent_deployment_statuses: recoveryEvidence.deployments.length,
  unresolved_recent_deployment_statuses: unresolvedEvidence.deployments.length,
  recent_failure_recoveries: recoveryEvidence,
  provisional_self_recoveries: provisionalEvidence,
  unresolved_recent_failures: unresolvedEvidence,
  github_api_request_budget: maxRequests,
  github_api_requests: requestStats.requests,
  github_api_retries: requestStats.retries,
  github_api_rate_reserve: rateReserve,
  github_api_rate_remaining: requestStats.rate_remaining,
  github_api_rate_reset_at: requestStats.rate_reset_at,
  failures,
  warnings,
};

console.log(JSON.stringify(summary, null, 2));
await writeStepSummary(summary);

  if (failures.length > 0) process.exitCode = 1;
}

async function inspectRepository(repo) {
  const defaultBranch = String(repo.default_branch || 'main');
  const [allWorkflows, commit, recentRuns, recentCommits, recentPulls, branches, deploymentCollection] = await Promise.all([
    collectWorkflows(repo.name),
    api('/repos/' + owner + '/' + repo.name + '/commits/' + encodeURIComponent(defaultBranch)),
    collectRecentWorkflowRuns(repo.name),
    collectRecentCommits(repo.name, defaultBranch),
    collectRecentPulls(repo.name),
    collectBranches(repo.name),
    collectRecentDeploymentStatuses(repo.name),
  ]);
  const headSha = String(commit.sha || '');

  const defaultCommitShas = new Set(recentCommits.map((recentCommit) => String(recentCommit.sha || '')));
  defaultCommitShas.add(headSha);
  const nonDefaultBranches = branches.filter((branch) => branch.name !== defaultBranch
    && Date.parse(String(branch.commit?.committedDate || '')) >= cutoffMs);
  const branchCommitGroups = await mapLimit(nonDefaultBranches, 3, async (branch) => {
    const commits = await collectRecentCommits(repo.name, branch.name);
    return commits.filter((recentCommit) => !defaultCommitShas.has(String(recentCommit.sha || '')));
  });
  const pullCommitGroups = await mapLimit(recentPulls, 3, async (pull) => collectRecentPullCommits(repo.name, pull));
  const recentBranchCommits = branchCommitGroups.flat();
  const recentPullCommits = pullCommitGroups.flat();

  const workflows = allWorkflows.filter((workflow) => workflow.state === 'active');
  const verifiedForwardFixPolicies = await resolveForwardFixRecoveryPolicies(
    repo.name,
    workflows,
    headSha,
  );
  await addVerifiedForwardFixOriginShas({
    repoName: repo.name,
    runs: recentRuns,
    currentHeadSha: headSha,
    defaultBranch,
    defaultCommitShas,
    policies: verifiedForwardFixPolicies,
  });
  const pullByNumber = new Map(recentPulls.map((pull) => [Number(pull.number), pull]));
  const workflowHealth = await mapLimit(workflows, 5, async (workflow) => {
    const recentCandidates = recentRuns
      .filter((run) => run.workflow_id === workflow.id && run.head_branch === defaultBranch)
      .sort((left, right) => recordOccurrenceTime(right) - recordOccurrenceTime(left));
    let run = recentCandidates[0] || null;
    if (!run) {
      const payload = await api('/repos/' + owner + '/' + repo.name + '/actions/workflows/' + workflow.id + '/runs?branch=' + encodeURIComponent(defaultBranch) + '&per_page=1');
      run = payload.workflow_runs?.[0] || null;
    }

    const key = repo.name + ':' + workflow.name;
    if (!run) {
      const policy = noHistoryPolicies.get(key);
      const workflowSource = policy ? await collectWorkflowSource(repo.name, workflow.path, headSha) : null;
      const allowance = evaluateNoHistoryAllowance({
        workflow,
        policy,
        workflowSource,
        workflows: allWorkflows,
        runs: recentRuns,
        defaultBranch,
        expectedHeadSha: headSha,
        nowMs,
      });
      if (!allowance.allowed) {
        failures.push(issue(repo.name, workflow.name, 'active workflow has no default-branch run history; ' + allowance.reason));
      } else {
        const witnessText = allowance.witness ? ' Witness run ' + allowance.witness.run_id + ' is current.' : '';
        warnings.push(repo.name + ' / ' + workflow.name + ' has no run history under an exact manual-control allowance.' + witnessText);
      }
      return {
        repo: repo.name,
        name: workflow.name,
        id: workflow.id,
        status: 'no_history',
        conclusion: 'no_history',
        run_id: null,
        url: workflow.html_url,
        allowed_no_history: allowance.allowed,
        no_history_reason: allowance.reason,
        no_history_source_sha256: allowance.workflow_source_sha256 || null,
        no_history_witness: allowance.witness,
      };
    }

    const ageMs = nowMs - recordOccurrenceTime(run);
    const conclusion = String(run.conclusion || '');
    if (run.status === 'completed' && !acceptableConclusions.has(conclusion)) {
      failures.push(issue(repo.name, workflow.name, 'latest run ' + run.id + ' concluded ' + conclusion, workflowRunUrl(run)));
    } else if (run.status !== 'completed' && ageMs > stuckMs) {
      failures.push(issue(repo.name, workflow.name, 'run ' + run.id + ' is stuck in ' + run.status + ' for more than ' + stuckMinutes + ' minutes', workflowRunUrl(run)));
    }
    return { repo: repo.name, name: workflow.name, id: workflow.id, status: run.status, conclusion, run_id: run.id, url: workflowRunUrl(run) };
  });

  reconcileWorkflowFailures(repo.name, recentRuns, {
    currentHeadSha: headSha,
    defaultBranch,
    defaultCommitShas,
    policies: verifiedForwardFixPolicies,
  });

  const shaMetadata = new Map();
  for (const run of recentRuns.filter((candidate) => recordActivityTime(candidate) >= cutoffMs || Number(candidate.id) === currentRunId)) {
    addShaMetadata(
      shaMetadata,
      run.head_sha,
      run.head_branch,
      run.event,
      'actions-run',
      false,
      run.head_repository?.full_name,
      (run.pull_requests || []).map((pull) => pull.number),
    );
  }
  const baseRepository = owner + '/' + repo.name;
  for (const recentCommit of recentCommits) addShaMetadata(shaMetadata, recentCommit.sha, defaultBranch, 'push', 'default-branch-commit', true, baseRepository);
  for (const recentCommit of recentBranchCommits) addShaMetadata(shaMetadata, recentCommit.sha, recentCommit._branch, 'push', 'branch-commit', false, baseRepository);
  for (const recentCommit of recentPullCommits) addShaMetadata(shaMetadata, recentCommit.sha, recentCommit._branch, 'pull_request', 'pull-request-commit', false, recentCommit._head_repository, [recentCommit._pull_number]);
  for (const branch of branches.filter((candidate) => candidate.name === defaultBranch
    || Date.parse(String(candidate.commit?.committedDate || '')) >= cutoffMs)) {
    addShaMetadata(shaMetadata, branch.commit?.oid, branch.name, 'branch_head', 'branch-head', branch.name === defaultBranch, baseRepository);
  }
  for (const pull of recentPulls) {
    addShaMetadata(shaMetadata, pull.head?.sha, pull.head?.ref, 'pull_request', 'pull-request-head', false, pull.head?.repo?.full_name, [pull.number]);
    if (pull.merged_at) {
      addShaMetadata(shaMetadata, pull.merge_commit_sha, defaultBranch, 'push', 'pull-request-merge', true, baseRepository, [pull.number]);
    }
  }
  for (const deployment of deploymentCollection.deployments) addShaMetadata(shaMetadata, deployment.sha, branchLikeRef(deployment.ref), 'deployment', 'deployment', false, baseRepository);
  addShaMetadata(shaMetadata, headSha, defaultBranch, 'push', 'default-branch-head', true, baseRepository);

  const [recentCheckPayload, currentHeadChecks, commitStatuses] = await Promise.all([
    collectRecentChecks(repo.name, shaMetadata),
    collectCurrentChecks(repo.name, headSha),
    collectRecentCommitStatuses(repo.name, shaMetadata, headSha),
  ]);
  const checks = associateChecksWithPulls(
    await enrichChecks(
      repo.name,
      [...recentCheckPayload, ...currentHeadChecks],
      recentRuns,
      shaMetadata,
      defaultBranch,
      verifiedForwardFixPolicies,
    ),
    recentPulls,
  );
  const statuses = enrichCommitStatuses(commitStatuses, shaMetadata, defaultBranch);
  const deploymentStatuses = enrichDeploymentStatuses(deploymentCollection.statuses, checks);

  reconcileCheckFailures(repo.name, checks, deploymentStatuses, pullByNumber, defaultBranch, {
    currentHeadSha: headSha,
    defaultCommitShas,
    policies: verifiedForwardFixPolicies,
    runs: recentRuns,
  });
  reconcileCommitStatusFailures(repo.name, statuses);
  reconcileDeploymentFailures(repo.name, deploymentStatuses);

  const latestChecks = latestByIdentity(
    checks.filter((check) => check.head_sha === headSha),
    (check) => check.stream_identity,
  );
  const currentChecks = latestChecks.map((check) => {
    const ageMs = nowMs - recordOccurrenceTime(check);
    const conclusion = String(check.conclusion || '');
    const policy = verifiedForwardFixPolicies.get(Number(check.workflow_id));
    const trustedMonitorPolicy = isTrustedMonitorRecoveryPolicy(policy) ? policy : null;
    const trustedMonitorRecovery = !trustedMonitorPolicy ? null : findTrustedMonitorCheckRecovery(check, checks, {
      policy: trustedMonitorPolicy,
      currentHeadSha: headSha,
      defaultBranch,
      defaultCommitShas,
    });
    const trustedMonitorCurrent = trustedMonitorRecovery || !trustedMonitorPolicy
      ? null
      : findProvisionalTrustedMonitorCheckRecovery(
      check,
      checks,
      currentRunId,
      currentRunAttempt,
      { policy: trustedMonitorPolicy, currentHeadSha: headSha, defaultBranch, defaultCommitShas },
    );
    const trustedMonitorCurrentRun = trustedMonitorRecovery || trustedMonitorCurrent || !trustedMonitorPolicy
      ? null
      : findProvisionalTrustedMonitorCheckRecoveryFromRun(
        check,
        recentRuns,
        currentRunId,
        currentRunAttempt,
        { policy: trustedMonitorPolicy, currentHeadSha: headSha, defaultBranch, defaultCommitShas },
      );
    const trustedMonitorRecheck = trustedMonitorRecovery || trustedMonitorCurrent || trustedMonitorCurrentRun;
    if (check.status === 'completed' && failedConclusions.has(conclusion) && !trustedMonitorRecheck) {
      failures.push(issue(repo.name, check.name, 'current commit check concluded ' + conclusion, check.details_url));
    } else if (check.status !== 'completed' && ageMs > stuckMs) {
      failures.push(issue(repo.name, check.name, 'current commit check is stuck in ' + check.status + ' for more than ' + stuckMinutes + ' minutes', check.details_url));
    }
    return {
      name: check.name,
      stream: check.stream_identity,
      status: check.status,
      conclusion,
      url: check.details_url,
      recovered_by_trusted_monitor_recheck: Boolean(trustedMonitorRecheck),
    };
  });

  const latestStatuses = latestByIdentity(
    statuses.filter((status) => status.sha === headSha),
    (status) => status.stream_identity,
  );
  const currentStatuses = latestStatuses.map((status) => {
    const ageMs = nowMs - recordOccurrenceTime(status);
    if (['error', 'failure'].includes(status.state)) {
      failures.push(issue(repo.name, status.context, 'current commit status is ' + status.state, status.target_url));
    } else if (status.state === 'pending' && ageMs > stuckMs) {
      failures.push(issue(repo.name, status.context, 'current commit status is pending for more than ' + stuckMinutes + ' minutes', status.target_url));
    }
    return { name: status.context, stream: status.stream_identity, status: status.state, conclusion: status.state, url: status.target_url };
  });

  rows.push({ repo: repo.name, default_branch: defaultBranch, head_sha: headSha, workflows: workflowHealth, checks: currentChecks, statuses: currentStatuses });
}

async function collectRecentWorkflowRuns(repoName) {
  const runs = [];
  let stoppedAtOriginBoundary = false;
  for (let page = 1; page <= pageLimits.runs; page += 1) {
    const payload = await api('/repos/' + owner + '/' + repoName + '/actions/runs?per_page=100&page=' + page);
    const batch = Array.isArray(payload.workflow_runs) ? payload.workflow_runs : [];
    runs.push(...batch.filter((run) => {
      const created = Date.parse(String(run.created_at || ''));
      return recordActivityTime(run) >= cutoffMs || (Number.isFinite(created) && created >= rerunOriginCutoffMs);
    }));
    const oldestCreated = minimumTimestamp(batch, 'created_at');
    if (batch.length < 100) {
      stoppedAtOriginBoundary = true;
      break;
    }
    if (Number.isFinite(oldestCreated) && oldestCreated < rerunOriginCutoffMs) {
      stoppedAtOriginBoundary = true;
      break;
    }
    if (page === pageLimits.runs) throw truncationError(repoName, 'workflow runs', pageLimits.runs);
  }
  if (!stoppedAtOriginBoundary && runs.length === 0) throw truncationError(repoName, 'workflow runs', pageLimits.runs);

  if (repoName === currentRepoName && currentRunId && !runs.some((run) => Number(run.id) === currentRunId)) {
    const current = await api('/repos/' + owner + '/' + repoName + '/actions/runs/' + currentRunId);
    runs.push(current);
  }

  const attemptRuns = [];
  await mapLimit(runs.filter((run) => Number(run.run_attempt || 1) > 1 && recordActivityTime(run) >= cutoffMs), 5, async (run) => {
    const currentAttempt = Number(run.run_attempt || 1);
    for (let attemptNumber = 1; attemptNumber < currentAttempt; attemptNumber += 1) {
      const attempt = await api('/repos/' + owner + '/' + repoName + '/actions/runs/' + run.id + '/attempts/' + attemptNumber);
      attemptRuns.push({ ...attempt, _historical_attempt: true });
    }
  });

  const unique = new Map();
  for (const run of [...runs, ...attemptRuns]) {
    const identity = String(run.id) + ':' + String(run.run_attempt || 1);
    unique.set(identity, run);
  }
  return [...unique.values()];
}

async function collectWorkflows(repoName) {
  const workflows = [];
  let expectedTotal = null;
  for (let page = 1; page <= pageLimits.workflows; page += 1) {
    const payload = await api('/repos/' + owner + '/' + repoName + '/actions/workflows?per_page=100&page=' + page);
    const batch = Array.isArray(payload.workflows) ? payload.workflows : null;
    const reportedTotal = Number(payload.total_count);
    if (!batch || !Number.isSafeInteger(reportedTotal) || reportedTotal < 0) {
      throw new Error(repoName + ' workflow list returned an invalid response.');
    }
    if (expectedTotal === null) expectedTotal = reportedTotal;
    if (reportedTotal !== expectedTotal) {
      throw new Error(repoName + ' workflow inventory changed during pagination. Retry the fail-closed scan.');
    }
    workflows.push(...batch);
    if (workflows.length >= expectedTotal) return workflows.slice(0, expectedTotal);
    if (batch.length < 100) {
      throw new Error(repoName + ' workflow inventory ended before its reported total of ' + expectedTotal + '.');
    }
    if (page === pageLimits.workflows) throw truncationError(repoName, 'workflows', pageLimits.workflows);
  }
  throw truncationError(repoName, 'workflows', pageLimits.workflows);
}

async function collectWorkflowSource(repoName, workflowPath, ref) {
  const path = String(workflowPath || '').trim();
  if (!/^\.github\/workflows\/[A-Za-z0-9._-]+\.ya?ml$/.test(path)) {
    throw new Error(repoName + ' no-history policy references an unsafe workflow path.');
  }
  return collectRepositorySource(repoName, path, ref, false);
}

async function collectMonitorImplementationSource(repoName, sourcePath, ref, allowMissing = false) {
  const path = String(sourcePath || '').trim();
  if (!['scripts/verify-org-release-health.mjs', 'scripts/release-health-monitor-utils.mjs'].includes(path)) {
    throw new Error(repoName + ' audited monitor policy references an unsafe implementation path.');
  }
  return collectRepositorySource(repoName, path, ref, allowMissing);
}

async function collectRepositorySource(repoName, path, ref, allowMissing) {
  const encodedPath = path.split('/').map(encodeURIComponent).join('/');
  const pathname = '/repos/' + owner + '/' + repoName + '/contents/' + encodedPath + '?ref=' + encodeURIComponent(ref);
  const payload = allowMissing ? await apiOptional(pathname) : await api(pathname);
  if (payload === null) return null;
  const size = Number(payload?.size);
  const content = String(payload?.content || '').replace(/\s/g, '');
  if (payload?.type !== 'file' || payload?.encoding !== 'base64' || !Number.isSafeInteger(size) || size < 1 || size > 262_144
    || content.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(content)) {
    throw new Error(repoName + ' source response for ' + path + ' is invalid or exceeds the 256 KiB safety bound.');
  }
  const bytes = Buffer.from(content, 'base64');
  if (bytes.length !== size) throw new Error(repoName + ' source response for ' + path + ' failed its byte-length integrity check.');
  return bytes;
}

async function resolveForwardFixRecoveryPolicies(repoName, workflows, headSha) {
  const verified = new Map();
  const configured = [...forwardFixRecoveryPolicies.entries()]
    .filter(([key]) => key.startsWith(repoName + ':'))
    .map(([, policy]) => policy);
  await mapLimit(configured, 2, async (policy) => {
    const workflow = workflows.find((candidate) => Number(candidate.id) === Number(policy.workflowId));
    if (!workflow) {
      failures.push(issue(repoName, policy.path, 'configured recovery policy workflow is missing or inactive'));
      return;
    }
    const workflowSource = await collectWorkflowSource(repoName, policy.path, headSha);
    const auditedOriginSources = new Map();
    const auditedHeads = [...new Set((policy.auditedMonitorOrigins || []).map((origin) => origin.headSha))];
    await mapLimit(auditedHeads, 2, async (originHeadSha) => {
      const origin = policy.auditedMonitorOrigins.find((candidate) => candidate.headSha === originHeadSha);
      const [originWorkflowSource, scriptSource, utilsSource] = await Promise.all([
        collectWorkflowSource(repoName, policy.path, originHeadSha),
        collectMonitorImplementationSource(repoName, 'scripts/verify-org-release-health.mjs', originHeadSha),
        collectMonitorImplementationSource(
          repoName,
          'scripts/release-health-monitor-utils.mjs',
          originHeadSha,
          origin?.utilsSourceSha256 === null,
        ),
      ]);
      auditedOriginSources.set(originHeadSha, {
        workflowSource: originWorkflowSource,
        scriptSource,
        utilsSource,
      });
    });
    const resolved = verifyForwardFixRecoveryPolicy({
      workflow,
      policy,
      workflowSource,
      auditedOriginSources,
    });
    if (!resolved) {
      failures.push(issue(repoName, policy.path, 'configured recovery policy failed its exact workflow identity or source-digest verification'));
      return;
    }
    verified.set(resolved.workflowId, resolved);
  });
  return verified;
}

async function addVerifiedForwardFixOriginShas({
  repoName,
  runs,
  currentHeadSha,
  defaultBranch,
  defaultCommitShas,
  policies,
}) {
  const candidates = [...new Set(runs
    .filter((run) => {
      const policy = policies.get(Number(run.workflow_id));
      const eligibleOriginEvents = policy
        ? new Set([...policy.failedEvents, ...(policy.monitorSelfRecoveryEvents || [])])
        : null;
      return policy
        && run.head_branch === defaultBranch
        && run.head_repository?.full_name === policy.headRepository
        && eligibleOriginEvents.has(String(run.event || ''))
        && run.status === 'completed'
        && failedConclusions.has(String(run.conclusion || ''))
        && /^[a-f0-9]{40}$/i.test(String(run.head_sha || ''))
        && run.head_sha !== currentHeadSha
        && !defaultCommitShas.has(run.head_sha);
    })
    .map((run) => String(run.head_sha)))];
  await mapLimit(candidates, 2, async (originSha) => {
    const comparison = await api('/repos/' + owner + '/' + repoName + '/compare/'
      + encodeURIComponent(originSha) + '...' + encodeURIComponent(currentHeadSha));
    if (comparison?.status === 'ahead'
      && comparison?.base_commit?.sha === originSha
      && comparison?.merge_base_commit?.sha === originSha) {
      defaultCommitShas.add(originSha);
    }
  });
}

async function collectRecentCommits(repoName, defaultBranch) {
  const branch = String(defaultBranch || '').trim();
  if (!branch) return [];
  const commits = [];
  for (let page = 1; page <= pageLimits.commits; page += 1) {
    const batch = await api('/repos/' + owner + '/' + repoName + '/commits?sha=' + encodeURIComponent(defaultBranch) + '&since=' + encodeURIComponent(cutoffIso) + '&per_page=100&page=' + page);
    if (!Array.isArray(batch)) throw new Error(repoName + ' commit list returned an invalid response.');
    commits.push(...batch.map((commit) => ({ ...commit, _branch: branch })));
    if (batch.length < 100) break;
    if (page === pageLimits.commits) throw truncationError(repoName, 'default-branch commits', pageLimits.commits);
  }
  return commits;
}

async function collectBranches(repoName) {
  const branches = [];
  let cursor = null;
  for (let page = 1; page <= pageLimits.branches; page += 1) {
    const payload = await graphql(
      `query ReleaseHealthBranches($owner: String!, $name: String!, $cursor: String) {
        repository(owner: $owner, name: $name) {
          refs(refPrefix: "refs/heads/", first: 100, after: $cursor) {
            nodes { name target { ... on Commit { oid committedDate } } }
            pageInfo { hasNextPage endCursor }
          }
        }
      }`,
      { owner, name: repoName, cursor },
      repoName + ' branch inventory',
    );
    const connection = payload?.data?.repository?.refs;
    if (!connection || !Array.isArray(connection.nodes)) throw new Error(repoName + ' branch list returned an invalid response.');
    branches.push(...connection.nodes.map((branch) => ({ name: branch.name, commit: branch.target })));
    if (!connection.pageInfo?.hasNextPage) break;
    cursor = String(connection.pageInfo.endCursor || '');
    if (!cursor || page === pageLimits.branches) throw truncationError(repoName, 'branches', pageLimits.branches);
  }
  return branches;
}

async function collectRecentPulls(repoName) {
  const pulls = [];
  for (let page = 1; page <= pageLimits.pulls; page += 1) {
    const batch = await api('/repos/' + owner + '/' + repoName + '/pulls?state=all&sort=updated&direction=desc&per_page=100&page=' + page);
    if (!Array.isArray(batch)) throw new Error(repoName + ' pull-request list returned an invalid response.');
    pulls.push(...batch.filter((pull) => Date.parse(String(pull.updated_at || '')) >= cutoffMs));
    const oldestUpdated = minimumTimestamp(batch, 'updated_at');
    if (batch.length < 100 || (Number.isFinite(oldestUpdated) && oldestUpdated < cutoffMs)) break;
    if (page === pageLimits.pulls) throw truncationError(repoName, 'recent pull requests', pageLimits.pulls);
  }
  return pulls;
}

async function collectRecentPullCommits(repoName, pull) {
  const pullNumber = Number(pull?.number);
  if (!Number.isSafeInteger(pullNumber) || pullNumber <= 0) return [];
  const branch = String(pull.head?.ref || '');
  const commits = [];
  for (let page = 1; page <= pageLimits.commits; page += 1) {
    const batch = await api('/repos/' + owner + '/' + repoName + '/pulls/' + pullNumber + '/commits?per_page=100&page=' + page);
    if (!Array.isArray(batch)) throw new Error(repoName + ' pull-request commit list returned an invalid response.');
    commits.push(...batch
      .filter((commit) => commitActivityTime(commit) >= cutoffMs)
      .map((commit) => ({
        ...commit,
        _branch: branch,
        _head_repository: String(pull.head?.repo?.full_name || ''),
        _pull_number: pullNumber,
      })));
    if (batch.length < 100) break;
    if (page === pageLimits.commits) throw truncationError(repoName, 'commits for pull request ' + pullNumber, pageLimits.commits);
  }
  return commits;
}

async function collectRecentChecks(repoName, shaMetadata) {
  const checks = [];
  await mapLimit([...shaMetadata.keys()], 5, async (sha) => {
    for (let page = 1; page <= pageLimits.checks; page += 1) {
      const payload = await api('/repos/' + owner + '/' + repoName + '/commits/' + sha + '/check-runs?filter=all&per_page=100&page=' + page);
      const batch = Array.isArray(payload.check_runs) ? payload.check_runs : [];
      checks.push(...batch.filter((check) => recordActivityTime(check) >= cutoffMs));
      // Check runs are ordered by creation, while an older run may transition or
      // complete inside the lookback. Enumerate the SHA independently instead of
      // assuming activity timestamps are monotonic across pages.
      if (batch.length < 100) break;
      if (page === pageLimits.checks) throw truncationError(repoName, 'check runs for ' + sha, pageLimits.checks);
    }
  });
  return uniqueById(checks);
}

async function collectCurrentChecks(repoName, headSha) {
  const checks = [];
  for (let page = 1; page <= pageLimits.checks; page += 1) {
    const payload = await api('/repos/' + owner + '/' + repoName + '/commits/' + headSha + '/check-runs?filter=latest&per_page=100&page=' + page);
    const batch = Array.isArray(payload.check_runs) ? payload.check_runs : [];
    checks.push(...batch);
    if (batch.length < 100) break;
    if (page === pageLimits.checks) throw truncationError(repoName, 'current check runs', pageLimits.checks);
  }
  return checks;
}

async function collectRecentCommitStatuses(repoName, shaMetadata, headSha) {
  const statuses = [];
  await mapLimit([...shaMetadata.keys()], 5, async (sha) => {
    for (let page = 1; page <= pageLimits.statuses; page += 1) {
      const batch = await api('/repos/' + owner + '/' + repoName + '/commits/' + sha + '/statuses?per_page=100&page=' + page);
      if (!Array.isArray(batch)) throw new Error(repoName + ' commit-status list returned an invalid response.');
      statuses.push(...batch.filter((status) => sha === headSha || recordActivityTime(status) >= cutoffMs).map((status) => ({ ...status, sha })));
      if (batch.length < 100) break;
      if (page === pageLimits.statuses) throw truncationError(repoName, 'commit statuses for ' + sha, pageLimits.statuses);
    }
  });
  return uniqueById(statuses);
}

async function collectRecentDeploymentStatuses(repoName) {
  const deployments = [];
  for (let page = 1; page <= pageLimits.deployments; page += 1) {
    const batch = await api('/repos/' + owner + '/' + repoName + '/deployments?per_page=100&page=' + page);
    if (!Array.isArray(batch)) throw new Error(repoName + ' deployment list returned an invalid response.');
    deployments.push(...batch.filter((deployment) => {
      const created = Date.parse(String(deployment.created_at || ''));
      const updated = Date.parse(String(deployment.updated_at || ''));
      const noObservedTransition = Number.isFinite(created) && Number.isFinite(updated) && Math.abs(updated - created) < 1000;
      return (Number.isFinite(created) && created >= cutoffMs - stuckMs)
        || (Number.isFinite(updated) && updated >= cutoffMs)
        || (noObservedTransition && created >= deploymentOriginCutoffMs);
    }));
    const oldestCreated = minimumTimestamp(batch, 'created_at');
    if (batch.length < 100 || (Number.isFinite(oldestCreated) && oldestCreated < deploymentOriginCutoffMs)) break;
    if (page === pageLimits.deployments) throw truncationError(repoName, 'deployments', pageLimits.deployments);
  }

  const statuses = [];
  await mapLimit(deployments, 6, async (deployment) => {
    const batch = await api('/repos/' + owner + '/' + repoName + '/deployments/' + deployment.id + '/statuses?per_page=100');
    if (!Array.isArray(batch)) throw new Error(repoName + ' deployment status list returned an invalid response.');
    if (batch.length === 100) throw truncationError(repoName, 'statuses for deployment ' + deployment.id, 1);
    if (batch.length === 0) {
      statuses.push({
        id: 'deployment-' + deployment.id,
        deployment_id: deployment.id,
        environment: deployment.environment,
        task: deployment.task,
        state: 'pending',
        created_at: deployment.created_at,
        updated_at: deployment.updated_at,
        ref: deployment.ref,
        sha: deployment.sha,
        url: deploymentUrl(repoName),
        log_url: '',
      });
      return;
    }
    statuses.push(...batch.map((status) => ({
      ...status,
      deployment_id: deployment.id,
      environment: deployment.environment,
      task: deployment.task,
      ref: deployment.ref,
      sha: deployment.sha,
      url: status.environment_url || status.log_url || deploymentUrl(repoName),
    })));
  });
  return { deployments, statuses };
}

async function enrichChecks(repoName, rawChecks, runs, shaMetadata, defaultBranch, policies) {
  const auditedOriginByCheckId = new Map();
  for (const policy of policies.values()) {
    for (const origin of policy.auditedMonitorOrigins || []) {
      if (auditedOriginByCheckId.has(origin.checkRunId)) {
        throw new Error(repoName + ' has duplicate audited monitor check identity ' + origin.checkRunId + '.');
      }
      auditedOriginByCheckId.set(origin.checkRunId, origin);
    }
  }
  const runById = new Map();
  for (const run of [...runs].sort((left, right) => recordOccurrenceTime(left) - recordOccurrenceTime(right))) {
    runById.set(Number(run.id), run);
  }
  const uniqueChecks = uniqueById(rawChecks);
  const missingRunIds = [...new Set(uniqueChecks
    .filter((check) => String(check.app?.slug || '') === 'github-actions')
    .map((check) => actionsRunId(check.details_url))
    .filter((runId) => runId && !runById.has(runId)))];
  await mapLimit(missingRunIds, 4, async (runId) => {
    const run = await api('/repos/' + owner + '/' + repoName + '/actions/runs/' + runId);
    runById.set(runId, run);
  });

  return uniqueChecks.map((check) => {
    const sourceRunId = actionsRunId(check.details_url);
    const sourceRun = sourceRunId ? runById.get(sourceRunId) : null;
    const auditedOrigin = auditedOriginByCheckId.get(Number(check.id));
    const metadata = shaMetadata.get(String(check.head_sha || ''));
    const branch = sourceRun?.head_branch || authoritativeCheckBranch(check, metadata, defaultBranch);
    const headRepository = String(sourceRun?.head_repository?.full_name
      || authoritativeCheckHeadRepository(check, metadata)
      || '');
    const enriched = {
      ...check,
      source_run_id: sourceRunId || null,
      source_run_attempt: Number(auditedOrigin?.runAttempt || sourceRun?.run_attempt || 1),
      workflow_id: sourceRun?.workflow_id || null,
      event: sourceRun?.event || '',
      source_run_display_title: sourceRun?.display_title || '',
      head_branch: branch,
      head_repository: headRepository,
      pull_numbers: authoritativePullNumbers(check, sourceRun, metadata),
    };
    enriched.stream_identity = checkStreamIdentity(enriched);
    return enriched;
  });
}

function enrichCommitStatuses(rawStatuses, shaMetadata, defaultBranch) {
  return rawStatuses.map((status) => {
    const metadata = shaMetadata.get(String(status.sha || ''));
    const branch = authoritativeMetadataBranch(metadata, defaultBranch);
    const enriched = { ...status, head_branch: branch, head_repository: authoritativeMetadataHeadRepository(metadata) };
    enriched.stream_identity = commitStatusStreamIdentity(enriched);
    return enriched;
  });
}

function enrichDeploymentStatuses(rawStatuses, checks) {
  const checkByJobId = new Map();
  for (const check of checks) {
    const jobId = actionsJobId(check.details_url);
    if (jobId) checkByJobId.set(jobId, check);
  }
  return rawStatuses.map((status) => {
    const jobId = actionsJobId(status.log_url);
    const sourceCheck = jobId ? checkByJobId.get(jobId) : null;
    const enriched = { ...status };
    if (sourceCheck) {
      enriched.deployment_job_identity = deploymentJobStreamIdentity(sourceCheck);
      enriched.stream_identity = [
        'deployment',
        encodeURIComponent(String(status.environment || 'unknown')),
        enriched.deployment_job_identity,
      ].join(':');
      enriched.identity_source = 'github-actions-job';
      enriched.source_check_run_id = sourceCheck.id;
    } else {
      enriched.stream_identity = deploymentStreamIdentity(enriched);
      enriched.identity_source = 'same-deployment-only';
      enriched.source_check_run_id = null;
      enriched.deployment_job_identity = '';
    }
    return enriched;
  });
}

function reconcileWorkflowFailures(repoName, runs, {
  currentHeadSha,
  defaultBranch,
  defaultCommitShas,
  policies,
}) {
  for (const run of runs.filter((candidate) => candidate.status === 'completed'
    && failedConclusions.has(String(candidate.conclusion || ''))
    && recordActivityTime(candidate) >= cutoffMs)) {
    const policy = policies.get(Number(run.workflow_id));
    const trustedMonitorPolicy = isTrustedMonitorRecoveryPolicy(policy) ? policy : null;
    const policyBoundRecovery = findPolicyBoundWorkflowRecovery(run, runs, policy, {
      currentHeadSha,
      defaultBranch,
      defaultCommitShas,
    });
    const directRecovery = trustedMonitorPolicy ? null : policyBoundRecovery;
    const trustedMonitorRecovery = trustedMonitorPolicy ? policyBoundRecovery : null;
    const forwardFixRecovery = policyBoundRecovery || trustedMonitorPolicy || !policy ? null : findForwardFixWorkflowRun(run, runs, {
      policy,
      currentHeadSha,
      defaultBranch,
      defaultCommitShas,
    });
    const recovery = directRecovery || trustedMonitorRecovery || forwardFixRecovery;
    const policyBoundCurrent = repoName === currentRepoName && currentRunId
      ? findPolicyBoundProvisionalWorkflowRecovery(
        run,
        runs,
        currentRunId,
        currentRunAttempt,
        policy,
        { currentHeadSha, defaultBranch, defaultCommitShas },
      )
      : null;
    const directCurrent = trustedMonitorPolicy ? null : policyBoundCurrent;
    const trustedMonitorCurrent = trustedMonitorPolicy ? policyBoundCurrent : null;
    const forwardFixCurrent = policyBoundCurrent || trustedMonitorPolicy || !policy ? null : findProvisionalForwardFixWorkflowRecovery(
      run,
      runs,
      currentRunId,
      currentRunAttempt,
      { policy, currentHeadSha, defaultBranch, defaultCommitShas },
    );
    const current = directCurrent || trustedMonitorCurrent || forwardFixCurrent;
    const evidence = {
      repo: repoName,
      workflow: String(run.name || run.workflow_id || 'unknown'),
      stream: workflowStreamIdentity(run),
      branch: String(run.head_branch || ''),
      event: String(run.event || ''),
      run_id: run.id,
      run_attempt: Number(run.run_attempt || 1),
      conclusion: String(run.conclusion || ''),
      url: workflowRunUrl(run),
      recovered_by_run_id: recovery?.id || null,
      recovered_by_attempt: recovery ? Number(recovery.run_attempt || 1) : null,
      recovery_url: recovery ? workflowRunUrl(recovery) : '',
      recovery_kind: directRecovery
        ? 'same-trigger-stream'
        : trustedMonitorRecovery
          ? 'trusted-monitor-recheck'
          : forwardFixRecovery
            ? 'verified-current-main-forward-fix'
            : '',
    };
    if (recovery) {
      recoveryEvidence.workflows.push(evidence);
    } else if (current) {
      provisionalEvidence.workflows.push({
        ...evidence,
        provisional_recovery_run_id: current.id,
        provisional_recovery_attempt: Number(current.run_attempt || 1),
        provisional_recovery_kind: directCurrent
          ? 'same-trigger-self-latch'
          : trustedMonitorCurrent
            ? 'trusted-monitor-recheck-self-latch'
            : 'verified-current-main-forward-fix-self-latch',
      });
    } else {
      unresolvedEvidence.workflows.push(evidence);
      failures.push(issue(repoName, evidence.workflow, 'recent ' + evidence.event + ' run ' + evidence.run_id + ' attempt ' + evidence.run_attempt + ' concluded ' + evidence.conclusion + ' without a later same-trigger success, trusted monitor recheck, or verified current-main forward fix', evidence.url));
    }
  }
}

function reconcileCheckFailures(repoName, checks, deploymentStatuses, pullByNumber, defaultBranch, {
  currentHeadSha,
  defaultCommitShas,
  policies,
  runs,
}) {
  for (const check of checks.filter((candidate) => candidate.status === 'completed'
    && failedConclusions.has(String(candidate.conclusion || ''))
    && recordActivityTime(candidate) >= cutoffMs)) {
    const policy = policies.get(Number(check.workflow_id));
    const trustedMonitorPolicy = isTrustedMonitorRecoveryPolicy(policy) ? policy : null;
    const policyBoundRecovery = findPolicyBoundCheckRecovery(check, checks, policy, {
      currentHeadSha,
      defaultBranch,
      defaultCommitShas,
    });
    const directRecovery = trustedMonitorPolicy ? null : policyBoundRecovery;
    const trustedMonitorRecovery = trustedMonitorPolicy ? policyBoundRecovery : null;
    const forwardFixRecovery = policyBoundRecovery || trustedMonitorPolicy || !policy ? null : findForwardFixCheck(check, checks, {
      policy,
      currentHeadSha,
      defaultBranch,
      defaultCommitShas,
    });
    const deploymentRecovery = policyBoundRecovery || trustedMonitorPolicy || forwardFixRecovery
      ? null
      : findDeploymentCheckRecovery(check, deploymentStatuses, checks);
    const mergedPullRecovery = policyBoundRecovery || trustedMonitorPolicy || forwardFixRecovery || deploymentRecovery
      ? null
      : findMergedPullCheckRecovery(check, checks, pullByNumber, defaultBranch);
    const recovery = directRecovery || trustedMonitorRecovery || forwardFixRecovery
      || deploymentRecovery?.check || mergedPullRecovery?.check || null;
    const policyBoundCurrent = repoName === currentRepoName && currentRunId
      ? findPolicyBoundProvisionalCheckRecovery(
        check,
        checks,
        currentRunId,
        currentRunAttempt,
        policy,
        { currentHeadSha, defaultBranch, defaultCommitShas },
      )
      : null;
    const directCurrent = trustedMonitorPolicy ? null : policyBoundCurrent;
    const trustedMonitorCurrent = trustedMonitorPolicy ? policyBoundCurrent : null;
    const trustedMonitorCurrentRun = policyBoundCurrent || !trustedMonitorPolicy
      ? null
      : findProvisionalTrustedMonitorCheckRecoveryFromRun(
        check,
        runs,
        currentRunId,
        currentRunAttempt,
        { policy: trustedMonitorPolicy, currentHeadSha, defaultBranch, defaultCommitShas },
      );
    const forwardFixCurrent = policyBoundCurrent || trustedMonitorCurrentRun || trustedMonitorPolicy || !policy
      ? null
      : findProvisionalForwardFixCheckRecovery(
        check,
        checks,
        currentRunId,
        currentRunAttempt,
        { policy, currentHeadSha, defaultBranch, defaultCommitShas },
      );
    const current = directCurrent || trustedMonitorCurrent || trustedMonitorCurrentRun || forwardFixCurrent;
    const evidence = {
      repo: repoName,
      check: String(check.name || 'unknown'),
      stream: check.stream_identity,
      provider: String(check.app?.slug || check.app?.id || 'unknown-app'),
      branch: String(check.head_branch || ''),
      head_sha: String(check.head_sha || ''),
      check_run_id: check.id,
      conclusion: String(check.conclusion || ''),
      url: String(check.details_url || ''),
      recovered_by_check_run_id: recovery?.id || null,
      recovery_url: String(recovery?.details_url || ''),
      recovery_kind: directRecovery
        ? 'same-trigger-stream'
        : trustedMonitorRecovery
          ? 'trusted-monitor-recheck'
          : forwardFixRecovery
            ? 'verified-current-main-forward-fix'
            : deploymentRecovery
              ? 'successful-deployment'
              : mergedPullRecovery
                ? 'merged-pull-default-branch'
                : '',
    };
    if (recovery) {
      recoveryEvidence.checks.push(evidence);
    } else if (current) {
      provisionalEvidence.checks.push({
        ...evidence,
        provisional_recovery_check_run_id: trustedMonitorCurrentRun ? null : current.id,
        provisional_recovery_run_id: trustedMonitorCurrentRun ? current.id : null,
        provisional_recovery_kind: directCurrent
          ? 'same-trigger-self-latch'
          : trustedMonitorCurrent || trustedMonitorCurrentRun
            ? 'trusted-monitor-recheck-self-latch'
            : 'verified-current-main-forward-fix-self-latch',
      });
    } else {
      unresolvedEvidence.checks.push(evidence);
      failures.push(issue(repoName, evidence.check, 'recent ' + evidence.provider + ' check ' + evidence.check_run_id + ' concluded ' + evidence.conclusion + ' without a later success in stream ' + evidence.stream, evidence.url));
    }
  }
}

function reconcileCommitStatusFailures(repoName, statuses) {
  for (const status of statuses.filter((candidate) => ['error', 'failure'].includes(String(candidate.state || ''))
    && recordActivityTime(candidate) >= cutoffMs)) {
    const recovery = findSupersedingCommitStatus(status, statuses);
    const evidence = {
      repo: repoName,
      context: String(status.context || 'unknown'),
      stream: status.stream_identity,
      branch: String(status.head_branch || ''),
      sha: String(status.sha || ''),
      status_id: status.id,
      state: String(status.state || ''),
      url: String(status.target_url || ''),
      recovered_by_status_id: recovery?.id || null,
      recovery_url: String(recovery?.target_url || ''),
    };
    if (recovery) {
      recoveryEvidence.statuses.push(evidence);
    } else {
      unresolvedEvidence.statuses.push(evidence);
      failures.push(issue(repoName, evidence.context, 'recent commit status ' + evidence.status_id + ' entered ' + evidence.state + ' without a later success in stream ' + evidence.stream, evidence.url));
    }
  }
}

function reconcileDeploymentFailures(repoName, statuses) {
  for (const status of statuses.filter((candidate) => failedDeploymentStates.has(String(candidate.state || ''))
    && recordActivityTime(candidate) >= cutoffMs)) {
    const recovery = findSupersedingDeployment(status, statuses);
    const evidence = {
      repo: repoName,
      environment: String(status.environment || 'unknown'),
      stream: status.stream_identity,
      identity_source: status.identity_source,
      deployment_id: status.deployment_id,
      deployment_status_id: status.id,
      state: String(status.state || ''),
      ref: String(status.ref || ''),
      sha: String(status.sha || ''),
      url: String(status.url || ''),
      recovered_by_deployment_id: recovery?.deployment_id || null,
      recovered_by_status_id: recovery?.id || null,
      recovery_url: String(recovery?.url || ''),
    };
    if (recovery) {
      recoveryEvidence.deployments.push(evidence);
    } else {
      unresolvedEvidence.deployments.push(evidence);
      const metadataProblem = status.identity_source === 'same-deployment-only'
        ? ' Stable cross-deployment job metadata was unavailable, so recovery is restricted to this deployment.'
        : '';
      failures.push(issue(repoName, evidence.environment, 'recent deployment ' + evidence.deployment_id + ' entered ' + evidence.state + ' without a later success in stream ' + evidence.stream + '.' + metadataProblem, evidence.url));
    }
  }

  const latestByDeployment = latestByIdentity(statuses, (status) => String(status.deployment_id));
  for (const status of latestByDeployment) {
    const ageMs = nowMs - recordOccurrenceTime(status);
    if (pendingDeploymentStates.has(String(status.state || '')) && ageMs > stuckMs) {
      failures.push(issue(repoName, status.environment, 'deployment ' + status.deployment_id + ' is stuck in ' + status.state + ' for more than ' + stuckMinutes + ' minutes', status.url));
    }
  }
}

async function listRepositories() {
  const all = [];
  for (let page = 1; page <= pageLimits.repositories; page += 1) {
    const batch = await api('/user/repos?affiliation=owner,organization_member&visibility=all&per_page=100&page=' + page);
    if (!Array.isArray(batch)) throw new Error('GitHub repository list returned an invalid response.');
    all.push(...batch);
    if (batch.length < 100) return all;
    if (page === pageLimits.repositories) throw truncationError(owner, 'repository list', pageLimits.repositories);
  }
  return all;
}

async function api(pathname) {
  return apiGate(() => apiRequest({
    label: pathname,
    url: 'https://api.github.com' + pathname,
    method: 'GET',
  }));
}

async function apiOptional(pathname) {
  return apiGate(() => apiRequest({
    label: pathname,
    url: 'https://api.github.com' + pathname,
    method: 'GET',
    allowNotFound: true,
  }));
}

async function graphql(query, variables, label) {
  return apiGate(async () => {
    const payload = await apiRequest({
      label,
      url: 'https://api.github.com/graphql',
      method: 'POST',
      body: JSON.stringify({ query, variables }),
    });
    if (Array.isArray(payload?.errors) && payload.errors.length) {
      const message = payload.errors.map((error) => String(error.message || 'unknown GraphQL error')).join('; ').slice(0, 500);
      throw new Error('GitHub GraphQL ' + label + ' returned errors: ' + message);
    }
    return payload;
  });
}

async function apiRequest({ label, url, method, body = undefined, allowNotFound = false }) {
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    enforceRequestBudget(label);
    requestStats.requests += 1;
    if (attempt > 1) requestStats.retries += 1;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20_000);
    try {
      const response = await fetch(url, {
        method,
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: 'Bearer ' + token,
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          'User-Agent': 'Scale-Small-AI-release-health-monitor',
          'X-GitHub-Api-Version': '2022-11-28',
        },
        body,
        signal: controller.signal,
      });
      updateRateBudget(response);
      if (response.ok) return await response.json();
      if (allowNotFound && response.status === 404) return null;
      const message = (await response.text()).slice(0, 500).replace(/\s+/g, ' ');
      lastError = new Error('GitHub API ' + label + ' returned HTTP ' + response.status + ': ' + message);
      if (!isRetryableResponse(response)) break;
      const delayMs = retryDelayMs(response, attempt);
      if (delayMs > 30_000) throw new Error('GitHub API requested a retry delay longer than the monitor safety limit for ' + label + '.');
      if (attempt < 3) await sleep(delayMs);
      continue;
    } catch (error) {
      lastError = error;
      if (attempt < 3 && (error?.name === 'AbortError' || error instanceof TypeError)) {
        await sleep(backoffWithJitter(attempt));
        continue;
      }
      break;
    } finally {
      clearTimeout(timeout);
    }
  }
  throw lastError || new Error('GitHub API request failed: ' + label);
}

function enforceRequestBudget(label) {
  if (requestStats.requests >= maxRequests) {
    throw new Error('GitHub API request budget exhausted at ' + requestStats.requests + '/' + maxRequests + ' before ' + label + '. The scan is incomplete and is failing closed.');
  }
  if (requestStats.rate_remaining !== null && requestStats.rate_remaining <= rateReserve) {
    throw new Error('GitHub API rate-limit reserve reached before ' + label + '. The scan is incomplete and is failing closed.');
  }
}

function updateRateBudget(response) {
  const remainingHeader = response.headers.get('x-ratelimit-remaining');
  if (remainingHeader !== null) {
    const remaining = Number(remainingHeader);
    if (Number.isFinite(remaining)) {
      requestStats.rate_remaining = requestStats.rate_remaining === null
        ? remaining
        : Math.min(requestStats.rate_remaining, remaining);
    }
  }
  const resetHeader = response.headers.get('x-ratelimit-reset');
  if (resetHeader !== null) {
    const resetSeconds = Number(resetHeader);
    if (Number.isFinite(resetSeconds)) requestStats.rate_reset_at = new Date(resetSeconds * 1000).toISOString();
  }
}

function isRetryableResponse(response) {
  if ([429, 500, 502, 503, 504].includes(response.status)) return true;
  return response.status === 403
    && (response.headers.get('retry-after') !== null || response.headers.get('x-ratelimit-remaining') === '0');
}

function retryDelayMs(response, attempt) {
  const retryAfter = Number(response.headers.get('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter >= 0) return Math.max(250, retryAfter * 1000) + jitterMs();
  const resetSeconds = Number(response.headers.get('x-ratelimit-reset'));
  if (Number.isFinite(resetSeconds) && resetSeconds > 0) {
    return Math.max(250, (resetSeconds * 1000) - Date.now()) + jitterMs();
  }
  return backoffWithJitter(attempt);
}

function backoffWithJitter(attempt) {
  return Math.min(10_000, (2 ** Math.max(0, attempt - 1)) * 750) + jitterMs();
}

function jitterMs() {
  return Math.floor(Math.random() * 251);
}

function createConcurrencyGate(limit) {
  let active = 0;
  const queue = [];
  const drain = () => {
    while (active < limit && queue.length) {
      const entry = queue.shift();
      active += 1;
      Promise.resolve()
        .then(entry.task)
        .then(entry.resolve, entry.reject)
        .finally(() => {
          active -= 1;
          drain();
        });
    }
  };
  return (task) => new Promise((resolve, reject) => {
    queue.push({ task, resolve, reject });
    drain();
  });
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  }));
  return results;
}

async function writeStepSummary(result) {
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (!path) return;
  const lines = [
    '# Scale Small AI release health',
    '',
    '- Deferred: ' + (result.deferred ? 'yes' : 'no'),
    '- Inventory complete: ' + (result.inventory_complete ? 'yes' : 'no'),
    '- Mode/lookback: ' + result.scan_mode + '/' + result.lookback_hours + 'h',
    '- Repositories: ' + result.repositories,
    '- Active workflows: ' + result.active_workflows,
    '- Green workflows: ' + result.green_workflows,
    '- Pending workflows: ' + result.pending_workflows,
    '- Failed workflows: ' + result.failed_workflows,
    '- Allowed no-history workflows: ' + result.allowed_no_history_workflows,
    '- Unresolved no-history workflows: ' + result.unresolved_no_history_workflows,
    '- Categorized workflows: ' + result.categorized_workflows + '/' + result.active_workflows,
    '- Current commit checks/statuses: ' + result.current_commit_checks,
    '- Workflow failures recovered/provisional/unresolved: ' + result.recovered_recent_workflow_attempts + '/' + result.provisional_self_recovering_workflow_attempts + '/' + result.unresolved_recent_workflow_attempts,
    '- Check failures recovered/provisional/unresolved: ' + result.recovered_recent_check_runs + '/' + result.provisional_self_recovering_check_runs + '/' + result.unresolved_recent_check_runs,
    '- Commit-status failures recovered/unresolved: ' + result.recovered_recent_commit_statuses + '/' + result.unresolved_recent_commit_statuses,
    '- Deployment failures recovered/unresolved: ' + result.recovered_recent_deployment_statuses + '/' + result.unresolved_recent_deployment_statuses,
    '- GitHub API requests/budget/retries: ' + result.github_api_requests + '/' + result.github_api_request_budget + '/' + result.github_api_retries,
    '- Failures: ' + result.failures.length,
  ];
  if (result.deferred) lines.push('- Deferral reason: ' + result.deferred_reason);
  if (result.allowed_no_history_evidence.length) {
    lines.push('', '## Explicit no-history allowances', '', ...result.allowed_no_history_evidence.map((evidence) => {
      const witness = evidence.witness
        ? ' Witness: [' + evidence.witness.workflow + ' run ' + evidence.witness.run_id + '](' + safeMarkdownUrl(evidence.witness.url) + ') on `'
          + evidence.witness.head_sha + '` via `' + evidence.witness.event + '` from `' + evidence.witness.head_repository + '`.'
        : '';
      return '- ' + evidence.repo + ' / ' + evidence.workflow + ': ' + evidence.reason
        + ' Approved source SHA-256: `' + evidence.workflow_source_sha256 + '`.' + witness;
    }));
  }
  if (result.failures.length) {
    lines.push('', '## Failures', '', ...result.failures.map((failure) => '- ' + (failure.url ? '[' + failure.repo + ' / ' + failure.owner + '](' + safeMarkdownUrl(failure.url) + ')' : failure.repo + ' / ' + failure.owner) + ': ' + failure.problem));
  }
  if (result.warnings.length) lines.push('', '## Warnings', '', ...result.warnings.map((warning) => '- ' + warning));
  await appendFile(path, lines.join('\n') + '\n', 'utf8');
}

function deferredRateSummary() {
  return {
    ok: null,
    deferred: true,
    inventory_complete: false,
    deferred_reason: 'Insufficient GitHub API quota to complete the bounded scan while preserving the configured reserve.',
    checked_at: new Date().toISOString(),
    owner,
    repository_prefix: repoPrefix,
    scan_mode: scanMode,
    repositories: 0,
    active_workflows: 0,
    green_workflows: 0,
    pending_workflows: 0,
    failed_workflows: 0,
    allowed_no_history_workflows: 0,
    unresolved_no_history_workflows: 0,
    categorized_workflows: 0,
    workflow_categories_complete: false,
    allowed_no_history_evidence: [],
    current_commit_checks: 0,
    lookback_hours: lookbackHours,
    lookback_started_at: cutoffIso,
    rerun_origin_hours: rerunOriginHours,
    deployment_origin_hours: deploymentOriginHours,
    recent_unsuccessful_workflow_attempts: 0,
    recovered_recent_workflow_attempts: 0,
    provisional_self_recovering_workflow_attempts: 0,
    unresolved_recent_workflow_attempts: 0,
    recent_failed_check_runs: 0,
    recovered_recent_check_runs: 0,
    provisional_self_recovering_check_runs: 0,
    unresolved_recent_check_runs: 0,
    recent_failed_commit_statuses: 0,
    recovered_recent_commit_statuses: 0,
    unresolved_recent_commit_statuses: 0,
    recent_failed_deployment_statuses: 0,
    recovered_recent_deployment_statuses: 0,
    unresolved_recent_deployment_statuses: 0,
    recent_failure_recoveries: { workflows: [], checks: [], statuses: [], deployments: [] },
    provisional_self_recoveries: { workflows: [], checks: [] },
    unresolved_recent_failures: { workflows: [], checks: [], statuses: [], deployments: [] },
    github_api_request_budget: maxRequests,
    github_api_requests: requestStats.requests,
    github_api_retries: requestStats.retries,
    github_api_rate_reserve: rateReserve,
    github_api_rate_remaining: requestStats.rate_remaining,
    github_api_rate_reset_at: requestStats.rate_reset_at,
    failures: [],
    warnings: ['Continuous scan deferred for API quota; a later scheduled run must complete the inventory.'],
  };
}

function addShaMetadata(metadataBySha, rawSha, rawBranch, rawEvent, source, isDefault = false, rawHeadRepository = '', rawPullNumbers = []) {
  const sha = String(rawSha || '').trim();
  if (!/^[a-f0-9]{40}$/i.test(sha)) return;
  const metadata = metadataBySha.get(sha) || { branches: new Set(), events: new Set(), sources: new Set(), headRepositories: new Set(), pullNumbers: new Set(), isDefault: false };
  const branch = String(rawBranch || '').trim();
  const event = String(rawEvent || '').trim();
  const headRepository = String(rawHeadRepository || '').trim();
  if (branch) metadata.branches.add(branch);
  if (event) metadata.events.add(event);
  if (headRepository) metadata.headRepositories.add(headRepository);
  for (const rawPullNumber of rawPullNumbers) {
    const pullNumber = Number(rawPullNumber);
    if (Number.isSafeInteger(pullNumber) && pullNumber > 0) metadata.pullNumbers.add(pullNumber);
  }
  metadata.sources.add(source);
  metadata.isDefault ||= isDefault;
  metadataBySha.set(sha, metadata);
}

function authoritativeCheckBranch(check, metadata, defaultBranch) {
  const pullBranches = new Set((check.pull_requests || []).map((pull) => String(pull.head?.ref || '')).filter(Boolean));
  if (pullBranches.size === 1) return [...pullBranches][0];
  return authoritativeMetadataBranch(metadata, defaultBranch);
}

function authoritativeCheckHeadRepository(check, metadata) {
  const pullRepositories = new Set((check.pull_requests || [])
    .map((pull) => String(pull.head?.repo?.full_name || ''))
    .filter(Boolean));
  if (pullRepositories.size === 1) return [...pullRepositories][0];
  return authoritativeMetadataHeadRepository(metadata);
}

function authoritativePullNumbers(check, sourceRun, metadata) {
  const numbers = new Set();
  for (const pull of check.pull_requests || []) {
    const number = Number(pull.number);
    if (Number.isSafeInteger(number) && number > 0) numbers.add(number);
  }
  for (const pull of sourceRun?.pull_requests || []) {
    const number = Number(pull.number);
    if (Number.isSafeInteger(number) && number > 0) numbers.add(number);
  }
  for (const number of metadata?.pullNumbers || []) numbers.add(number);
  return [...numbers].sort((left, right) => left - right);
}


function authoritativeMetadataHeadRepository(metadata) {
  if (!metadata || metadata.headRepositories.size !== 1) return '';
  return [...metadata.headRepositories][0];
}

function authoritativeMetadataBranch(metadata, defaultBranch) {
  if (!metadata) return '';
  if (metadata.branches.size === 1) return [...metadata.branches][0];
  if (metadata.isDefault && (metadata.branches.size === 0 || (metadata.branches.size === 1 && metadata.branches.has(defaultBranch)))) return defaultBranch;
  return '';
}

function branchLikeRef(ref) {
  const value = String(ref || '').trim();
  return /^[A-Za-z0-9._/-]{1,255}$/.test(value) && !/^[a-f0-9]{40}$/i.test(value) ? value : '';
}

function actionsRunId(url) {
  const match = String(url || '').match(/\/actions\/runs\/(\d+)/);
  return match ? Number(match[1]) : 0;
}

function actionsJobId(url) {
  const match = String(url || '').match(/\/actions\/runs\/\d+\/job\/(\d+)/);
  return match ? Number(match[1]) : 0;
}

function workflowRunUrl(run) {
  const base = String(run.html_url || '');
  return run._historical_attempt ? base + '/attempts/' + Number(run.run_attempt || 1) : base;
}

function deploymentUrl(repoName) {
  return 'https://github.com/' + owner + '/' + repoName + '/deployments';
}

function truncationError(repoName, resource, pages) {
  return new Error(repoName + ' ' + resource + ' reached the fail-closed pagination limit of ' + pages + ' pages before the scan boundary. Use incident mode or reduce the lookback.');
}

function uniqueById(records) {
  const unique = new Map();
  for (const record of records) unique.set(String(record.id), record);
  return [...unique.values()];
}

function minimumTimestamp(records, key) {
  const values = records.map((record) => Date.parse(String(record?.[key] || ''))).filter(Number.isFinite);
  return values.length ? Math.min(...values) : Number.NaN;
}

function commitActivityTime(commit) {
  const timestamps = [
    commit?.commit?.committer?.date,
    commit?.commit?.author?.date,
  ]
    .map((value) => Date.parse(value || ''))
    .filter(Number.isFinite);

  return timestamps.length > 0 ? Math.max(...timestamps) : 0;
}

function safeMarkdownUrl(value) {
  const text = String(value || '');
  return /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:[/?#][^\s()]*)?$/.test(text) ? text : '';
}

function issue(repo, ownerName, problem, url = '') {
  return {
    repo: safeSummaryText(repo),
    owner: safeSummaryText(ownerName || 'unknown'),
    problem: safeSummaryText(problem),
    url: safeMarkdownUrl(url),
  };
}

function safeSummaryText(value) {
  return String(value || '').replace(/[\r\n]+/g, ' ').replace(/[\[\]`]/g, '').slice(0, 1000);
}

function requiredSecret(value, name) {
  const text = String(value || '').trim();
  if (text.length < 20) throw new Error(name + ' is missing or too short.');
  return text;
}

function safeName(value, name) {
  const text = String(value || '').trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(text)) throw new Error(name + ' contains unsupported characters.');
  return text;
}

function enumValue(value, allowed, name) {
  const text = String(value || '').trim();
  if (!allowed.includes(text)) throw new Error(name + ' must be one of: ' + allowed.join(', ') + '.');
  return text;
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, number)) : fallback;
}

function boundedInteger(value, fallback, min, max) {
  return Math.trunc(boundedNumber(value, fallback, min, max));
}

function numericIdentifier(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : 0;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
