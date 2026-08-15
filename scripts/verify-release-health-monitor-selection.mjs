import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
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
  isControlledDisabledMonitorRecoveryWorkflow,
  isTrustedMonitorRecoveryPolicy,
  isEligibleTrustedMonitorImplementationCandidate,
  latestByIdentity,
  partitionWorkflowHealth,
  parseReleaseHealthDeliveryIdentity,
  recordActivityTime,
  recordOccurrenceTime,
  rateHeadroomDecision,
  releaseHealthDeliveryIdentity,
  verifyAuthorizedDisabledWorkflowHold,
  verifyForwardFixRecoveryPolicy,
  workflowStreamIdentity,
} from './release-health-monitor-utils.mjs';
import {
  decodeScheduledIncidentState,
  decodeScheduledIncidentStateOrNull,
  createScheduledIncidentStateRecord,
  checkFailureEpisodeAnchor,
  durableTrustedMonitorRecoveryChecks,
  durableTrustedMonitorRecoveryRuns,
  evaluateIncidentNotification,
  expectedInventoryDigest,
  executeReleaseHealthMonitorEntryPoint,
  fingerprintReleaseHealthIncident,
  incidentStateOutputLines,
  isExactManualIncidentRecoveryCheck,
  isExactManualIncidentRecoveryRun,
  isExactSelfMonitorEnvironmentDeployment,
  notificationStateHmac,
  releaseHealthActiveCheckDisposition,
  releaseHealthCheckRecentActivityTime,
  releaseHealthCheckPageDisposition,
  releaseHealthCheckSourceActivityFallback,
  releaseHealthCheckSourceRecentActivityFallback,
  releaseHealthPageLimits,
  releaseHealthLogPayload,
  mapLimit,
  renderReleaseHealthStepSummary,
  shouldSetDegradedExitCode,
  scheduledIncidentStateEnabled,
  validateInstallationRepositoryPage,
  validateReleaseHealthCheckRunPage,
  validateReleaseHealthCheckSourceRun,
  verifyExpectedInventoryAttestation,
  verifyInstallationRepositoryScope,
  auditedPriorMonitorWorkflowSourceSha256,
  currentMonitorWorkflowSourceSha256,
} from './verify-org-release-health.mjs';

const incidentDeliveryIdentity = 'run-30264003709-attempt-1';
assert.equal(
  releaseHealthDeliveryIdentity('30264003709', '1'),
  incidentDeliveryIdentity,
  'delivery identity must bind a public GitHub run and attempt without incident-derived data',
);
assert.deepEqual(
  parseReleaseHealthDeliveryIdentity(incidentDeliveryIdentity),
  { identity: incidentDeliveryIdentity, runId: '30264003709', runAttempt: '1' },
);
assert.throws(
  () => parseReleaseHealthDeliveryIdentity('run-0-attempt-1'),
  /delivery identity is invalid/,
  'delivery identity must reject non-GitHub run provenance',
);

const currentWorkflowSource = (await readFile(
  new URL('../.github/workflows/release-health-monitor.yml', import.meta.url),
  'utf8',
)).replace(/\r\n/g, '\n');
assert.equal(
  auditedPriorMonitorWorkflowSourceSha256,
  '3672ed17290279e20d75336e810d9327a59786c16a77332aa5be2f4adb0238a1',
  'historical audited monitor origins must preserve the exact prior workflow-byte digest',
);
assert.equal(
  currentMonitorWorkflowSourceSha256,
  createHash('sha256').update(currentWorkflowSource).digest('hex'),
  'current default-main monitor policy must bind the exact modified workflow bytes',
);
assert.notEqual(
  currentMonitorWorkflowSourceSha256,
  auditedPriorMonitorWorkflowSourceSha256,
  'current source attestation must not overwrite the historical audited workflow digest',
);
assert.deepEqual(
  incidentStateOutputLines(
    true,
    'ssai-release-health-state-v4-v1-at-2026-08-01T01-02-03-004Z',
    incidentDeliveryIdentity,
    {
      incident_state: 'incident',
      notification_outcome: 'new-or-worsened-incident',
    },
  ),
  [
    'scan_completed=true',
    'health_degraded=true',
    'incident_state_changed=true',
    'incident_state=incident',
    'notification_outcome=new-or-worsened-incident',
    'notification_reconciliation_required=true',
    'incident_delivery_identity=' + incidentDeliveryIdentity,
    'incident_state_cache_key=ssai-release-health-state-v4-v1-at-2026-08-01T01-02-03-004Z',
  ],
  'a durable new-or-worsened state must require delivery and bind the exact cache key',
);
assert.deepEqual(
  incidentStateOutputLines(false, '', incidentDeliveryIdentity, {
    incident_state: 'incident',
    notification_outcome: 'known-incident-suppressed',
  }),
  [
    'scan_completed=true',
    'health_degraded=false',
    'incident_state_changed=false',
    'incident_state=incident',
    'notification_outcome=known-incident-suppressed',
    'notification_reconciliation_required=true',
    'incident_delivery_identity=' + incidentDeliveryIdentity,
  ],
  'an unchanged known incident must still reconcile the managed issue idempotently',
);
assert.throws(
  () => incidentStateOutputLines(false, 'unexpected-cache-key', incidentDeliveryIdentity, {
    incident_state: 'healthy',
    notification_outcome: 'healthy',
  }),
  /cannot publish a cache key/,
);
assert.equal(
  shouldSetDegradedExitCode(1, false, {}),
  true,
  'a degraded manual or direct scan must retain its failing conclusion',
);
assert.equal(
  shouldSetDegradedExitCode(1, false, { SSAI_RELEASE_MONITOR_DEFER_DEGRADED_EXIT: 'true' }),
  false,
  'a completed scheduled incident may defer failure until durable delivery finishes',
);
assert.equal(
  shouldSetDegradedExitCode(1, true, {}),
  false,
  'an unchanged known scheduled incident remains suppressed after reconciliation',
);
assert.throws(() => shouldSetDegradedExitCode(-1, false, {}), /conclusion input is invalid/);

const incidentFailureA = {
  repo: 'SSAI_Dashboard',
  owner: 'Deploy Dashboard',
  problem: 'wording A',
  url: 'https://github.com/ScaleSmall/SSAI_Dashboard/actions/runs/100',
  incident_key: {
    repo: 'SSAI_Dashboard',
    type: 'workflow-run',
    workflow_id: 10,
    run_id: 100,
    run_attempt: 1,
    conclusion: 'failure',
  },
  notification_key: {
    repo: 'SSAI_Dashboard',
    type: 'workflow-run',
    stream_sha256: '1'.repeat(64),
    failure_class: 'failure',
    episode_anchor: 'no-prior-success',
  },
};
const incidentFailureB = {
  repo: 'SSAI_NAP_Entity',
  owner: 'Production lifecycle',
  problem: 'wording B',
  url: 'https://github.com/ScaleSmall/SSAI_NAP_Entity/actions/runs/200',
  incident_key: {
    repo: 'SSAI_NAP_Entity',
    type: 'check-run',
    check_run_id: 200,
    conclusion: 'failure',
  },
  notification_key: {
    repo: 'SSAI_NAP_Entity',
    type: 'check-run',
    stream_sha256: '2'.repeat(64),
    failure_class: 'failure',
    episode_anchor: 'no-prior-success',
  },
};
const fingerprintA = fingerprintReleaseHealthIncident([incidentFailureA]);
const fingerprintAB = fingerprintReleaseHealthIncident([incidentFailureA, incidentFailureB]);
assert.equal(
  fingerprintReleaseHealthIncident([{ ...incidentFailureA, problem: 'rewritten prose', url: 'https://example.invalid/changed' }]).incidentFingerprint,
  fingerprintA.incidentFingerprint,
  'incident fingerprints must ignore mutable prose and URLs',
);
assert.equal(
  fingerprintReleaseHealthIncident([incidentFailureB, incidentFailureA]).incidentFingerprint,
  fingerprintAB.incidentFingerprint,
  'incident fingerprints must be order-independent',
);
assert.equal(
  fingerprintReleaseHealthIncident([{ ...incidentFailureA, incident_key: { ...incidentFailureA.incident_key, run_id: 101 } }]).incidentFingerprint,
  fingerprintA.incidentFingerprint,
  'a new immutable run identity in the same incident stream must not change the notification fingerprint',
);
assert.equal(
  fingerprintReleaseHealthIncident([
    incidentFailureA,
    { ...incidentFailureA, incident_key: { ...incidentFailureA.incident_key, run_id: 101 } },
  ]).failureCount,
  1,
  'multiple immutable evidence rows for one stable incident cluster must count once',
);
assert.notEqual(
  fingerprintReleaseHealthIncident([{
    ...incidentFailureA,
    notification_key: { ...incidentFailureA.notification_key, failure_class: 'timed_out' },
  }]).incidentFingerprint,
  fingerprintA.incidentFingerprint,
  'a changed failure class must worsen the incident fingerprint',
);
assert.notEqual(
  fingerprintReleaseHealthIncident([{
    ...incidentFailureA,
    notification_key: { ...incidentFailureA.notification_key, stream_sha256: '3'.repeat(64) },
  }]).incidentFingerprint,
  fingerprintA.incidentFingerprint,
  'a distinct failing stream must worsen the incident fingerprint',
);
const policyFailureAtHeadA = {
  repo: 'SSAI_Shared',
  owner: '.github/workflows/release-health-monitor.yml',
  problem: 'configured recovery policy workflow is missing or inactive',
  incident_key: {
    repo: 'SSAI_Shared',
    type: 'recovery-policy-workflow-missing',
    workflow_id: 315630665,
    workflow_path: '.github/workflows/release-health-monitor.yml',
    head_sha: 'a'.repeat(40),
  },
  notification_key: {
    repo: 'SSAI_Shared',
    type: 'recovery-policy-workflow-missing',
    stream_sha256: '4'.repeat(64),
    failure_class: 'workflow-missing',
    episode_anchor: 'policy-head:' + 'a'.repeat(40),
    policy_head_sha: 'a'.repeat(40),
  },
};
assert.notEqual(
  fingerprintReleaseHealthIncident([{
    ...policyFailureAtHeadA,
    incident_key: { ...policyFailureAtHeadA.incident_key, head_sha: 'b'.repeat(40) },
    notification_key: {
      ...policyFailureAtHeadA.notification_key,
      episode_anchor: 'policy-head:' + 'b'.repeat(40),
      policy_head_sha: 'b'.repeat(40),
    },
  }]).incidentFingerprint,
  fingerprintReleaseHealthIncident([policyFailureAtHeadA]).incidentFingerprint,
  'the same recovery-policy failure on a different immutable head must change the incident fingerprint',
);
assert.throws(
  () => fingerprintReleaseHealthIncident([{ ...incidentFailureA, incident_key: null }]),
  /typed immutable incident key/,
  'untyped incident evidence must fail closed',
);
assert.throws(
  () => fingerprintReleaseHealthIncident([{ ...incidentFailureA, notification_key: null }]),
  /stable notification cluster key/,
  'untyped notification clusters must fail closed',
);
assert.throws(
  () => fingerprintReleaseHealthIncident([{
    ...incidentFailureA,
    notification_key: {
      repo: incidentFailureA.notification_key.repo,
      type: incidentFailureA.notification_key.type,
      failure_class: incidentFailureA.notification_key.failure_class,
      episode_anchor: incidentFailureA.notification_key.episode_anchor,
    },
  }]),
  /missing a stream/,
  'a notification cluster without a stable stream digest must fail closed',
);
assert.throws(
  () => fingerprintReleaseHealthIncident([{
    ...incidentFailureA,
    notification_key: { ...incidentFailureA.notification_key, stream_sha256: 'ABC' },
  }]),
  /missing a stream/,
  'a malformed notification stream digest must fail closed',
);

const attestedInventory = [
  { name: 'SSAI_AI_Audit', full_name: 'ScaleSmall/SSAI_AI_Audit', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Analytics_Reporting', full_name: 'ScaleSmall/SSAI_Analytics_Reporting', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Brand_Identity', full_name: 'ScaleSmall/SSAI_Brand_Identity', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_CI_Engine', full_name: 'ScaleSmall/SSAI_CI_Engine', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Connect', full_name: 'ScaleSmall/SSAI_Connect', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Content_Engine', full_name: 'ScaleSmall/SSAI_Content_Engine', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Dashboard', full_name: 'ScaleSmall/SSAI_Dashboard', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Database', full_name: 'ScaleSmall/SSAI_Database', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Intel', full_name: 'ScaleSmall/SSAI_Intel', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_LDP', full_name: 'ScaleSmall/SSAI_LDP', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Leads', full_name: 'ScaleSmall/SSAI_Leads', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_NAP_Entity', full_name: 'ScaleSmall/SSAI_NAP_Entity', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Onboarding', full_name: 'ScaleSmall/SSAI_Onboarding', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_PoW', full_name: 'ScaleSmall/SSAI_PoW', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Production_QA', full_name: 'ScaleSmall/SSAI_Production_QA', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_RR', full_name: 'ScaleSmall/SSAI_RR', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Shared', full_name: 'ScaleSmall/SSAI_Shared', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Test_Emulator', full_name: 'ScaleSmall/SSAI_Test_Emulator', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Video_Prompt_System', full_name: 'ScaleSmall/SSAI_Video_Prompt_System', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Website', full_name: 'ScaleSmall/SSAI_Website', owner: { login: 'ScaleSmall' }, archived: false },
  { name: 'SSAI_Workflows_Shared', full_name: 'ScaleSmall/SSAI_Workflows_Shared', owner: { login: 'ScaleSmall' }, archived: false },
];
const attestedInventorySha256 = expectedInventoryDigest(attestedInventory);
const reviewedInventorySha256 = '1b0f98d54264554fdc81d3f7d5b89e2324f9660ebe15526e49e878d2a932df4b';
const supersededInventorySha256 = 'b372264a22a6ca71ef22c8cbf4eb7ff37029a17ee943d36a13c423a2c4cbc69e';
assert.equal(
  attestedInventorySha256,
  reviewedInventorySha256,
  'the reviewed 21-repository inventory digest must include Connect exactly once',
);
assert.equal(
  verifyExpectedInventoryAttestation([...attestedInventory].reverse(), attestedInventorySha256),
  true,
  'the exact repository set must pass independent of API order',
);
assert.throws(
  () => verifyExpectedInventoryAttestation(attestedInventory, supersededInventorySha256),
  /completeness attestation/,
  'the superseded 20-repository inventory digest must fail closed',
);
assert.throws(
  () => verifyExpectedInventoryAttestation(
    attestedInventory.filter((repository) => repository.name !== 'SSAI_Connect'),
    attestedInventorySha256,
  ),
  /completeness attestation/,
  'an omitted Connect repository must fail inventory completeness',
);
assert.throws(
  () => verifyExpectedInventoryAttestation(
    [...attestedInventory, { full_name: 'ScaleSmall/SSAI_New_Private' }],
    attestedInventorySha256,
  ),
  /completeness attestation/,
  'an unreviewed extra repository must fail inventory completeness',
);

const installationPage = validateInstallationRepositoryPage({
  total_count: 2,
  repositories: attestedInventory.slice(0, 1),
}, null, 0);
assert.deepEqual(
  { totalCount: installationPage.totalCount, complete: installationPage.complete },
  { totalCount: 2, complete: false },
  'installation pagination must preserve the provider-declared total count',
);
assert.equal(
  validateInstallationRepositoryPage({
    total_count: 2,
    repositories: attestedInventory.slice(1, 2),
  }, installationPage.totalCount, 1).complete,
  true,
  'installation pagination must complete only at the exact declared total count',
);
assert.throws(
  () => validateInstallationRepositoryPage({ total_count: 3, repositories: [] }, 2, 1),
  /total changed/,
  'a changing installation total must fail closed',
);
assert.throws(
  () => validateInstallationRepositoryPage({ total_count: 1, repositories: attestedInventory }, null, 0),
  /exceeded/,
  'an oversized installation page must fail closed',
);
assert.equal(
  verifyInstallationRepositoryScope(attestedInventory, 'ScaleSmall', 'SSAI_', new Set()),
  true,
  'the exact selected-repository installation including Connect must pass scope validation',
);

for (const [label, repository] of [
  ['wrong owner', {
    name: 'SSAI_Dashboard',
    full_name: 'Unrelated/SSAI_Dashboard',
    owner: { login: 'Unrelated' },
    archived: false,
  }],
  ['wrong prefix', {
    name: 'hillcosite',
    full_name: 'ScaleSmall/hillcosite',
    owner: { login: 'ScaleSmall' },
    archived: false,
  }],
  ['malformed full name', {
    name: 'SSAI_Dashboard',
    full_name: 'ScaleSmall/SSAI_Shared',
    owner: { login: 'ScaleSmall' },
    archived: false,
  }],
  ['archived repository', {
    name: 'SSAI_Dashboard',
    full_name: 'ScaleSmall/SSAI_Dashboard',
    owner: { login: 'ScaleSmall' },
    archived: true,
  }],
]) {
  assert.throws(
    () => verifyInstallationRepositoryScope(
      [...attestedInventory, repository],
      'ScaleSmall',
      'SSAI_',
      new Set(),
    ),
    /outside the approved release-health scope/,
    `an installation repository with ${label} must fail closed`,
  );
}

const hostedPublicEnvironment = {
  GITHUB_ACTIONS: 'true',
  GITHUB_REPOSITORY: 'ScaleSmall/SSAI_Shared',
};
const bootstrapProbeSource = `
const hostedActions = String(process.env.GITHUB_ACTIONS || '').toLowerCase() === 'true';
try {
  const monitor = await import('./scripts/verify-org-release-health.mjs');
  await monitor.executeReleaseHealthMonitorEntryPoint(monitor.runReleaseHealthMonitor);
} catch (caught) {
  if (hostedActions) console.error('::error::Release-health monitor failed closed before aggregate reporting.');
  else console.error(caught instanceof Error ? caught.stack || caught.message : String(caught));
  process.exitCode = 1;
}`;
const bootstrapProbe = spawnSync(process.execPath, ['--input-type=module', '--eval', bootstrapProbeSource], {
  cwd: fileURLToPath(new URL('..', import.meta.url)),
  encoding: 'utf8',
  env: {
    ...process.env,
    GITHUB_ACTIONS: 'true',
    GITHUB_REPOSITORY: 'TransferredOrg/RenamedPublicMonitor',
    SSAI_RELEASE_MONITOR_OWNER: 'invalid/private/path',
    SSAI_RELEASE_MONITOR_GITHUB_TOKEN: 'read-token-'.repeat(4),
    SSAI_RELEASE_MONITOR_STATE_HMAC_KEY: 'state-key-'.repeat(4),
    SSAI_RELEASE_MONITOR_STATE_HMAC_EPOCH: 'v1',
    SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256: 'a'.repeat(64),
  },
});
assert.equal(bootstrapProbe.status, 1, 'hosted bootstrap must fail nonzero on module-initialization errors');
assert.equal(bootstrapProbe.stdout, '', 'hosted bootstrap module-initialization failures must not write stdout');
assert.equal(
  bootstrapProbe.stderr,
  '::error::Release-health monitor failed closed before aggregate reporting.\n',
  'hosted bootstrap must redact an invalid top-level configuration exception and stack',
);
const directHostedProbe = spawnSync(process.execPath, ['scripts/verify-org-release-health.mjs'], {
  cwd: fileURLToPath(new URL('..', import.meta.url)),
  encoding: 'utf8',
  env: {
    ...process.env,
    GITHUB_ACTIONS: 'true',
    GITHUB_REPOSITORY: 'TransferredOrg/RenamedPublicMonitor',
    SSAI_RELEASE_MONITOR_OWNER: 'invalid/private/path',
    SSAI_RELEASE_MONITOR_GITHUB_TOKEN: 'read-token-'.repeat(4),
    SSAI_RELEASE_MONITOR_STATE_HMAC_KEY: 'state-key-'.repeat(4),
    SSAI_RELEASE_MONITOR_STATE_HMAC_EPOCH: 'v1',
    SSAI_RELEASE_MONITOR_EXPECTED_INVENTORY_SHA256: 'a'.repeat(64),
  },
});
assert.equal(directHostedProbe.status, 1, 'direct hosted execution must fail nonzero on invalid configuration');
assert.equal(directHostedProbe.stdout, '', 'direct hosted configuration failures must not write stdout');
assert.equal(
  directHostedProbe.stderr,
  '::error::Release-health monitor failed closed before aggregate reporting.\n',
  'direct hosted execution must also redact configuration errors and stacks',
);
const sensitiveMarkers = [
  'SSAI_Private_Fleet',
  'Private deploy workflow',
  'Private check name',
  'Private deployment environment',
  'https://github.com/ScaleSmall/SSAI_Private_Fleet/actions/runs/987654321012345',
  '987654321012345',
  'fedcba9876543210fedcba9876543210fedcba98',
  'private failure diagnostic text',
  'private no-history witness detail',
  '1111222233334444555566667777888899990000111122223333444455556666',
  '876543210123456',
];
const adversarialHostedResult = {
  ok: false,
  deferred: false,
  inventory_complete: true,
  scan_mode: 'incident',
  lookback_hours: 168,
  repositories: 9,
  active_workflows: 27,
  green_workflows: 25,
  pending_workflows: 0,
  failed_workflows: 2,
  allowed_no_history_workflows: 1,
  unresolved_no_history_workflows: 1,
  authorized_disabled_workflow_holds: 1,
  categorized_workflows: 27,
  current_commit_checks: 42,
  recovered_recent_workflow_attempts: 3,
  provisional_self_recovering_workflow_attempts: 1,
  unresolved_recent_workflow_attempts: 2,
  recovered_recent_check_runs: 3,
  provisional_self_recovering_check_runs: 1,
  unresolved_recent_check_runs: 2,
  recovered_recent_commit_statuses: 3,
  unresolved_recent_commit_statuses: 2,
  recovered_recent_deployment_statuses: 3,
  unresolved_recent_deployment_statuses: 2,
  github_api_requests: 777,
  github_api_retries: 4,
  notification_outcome: 'new-or-worsened-incident',
  incident_failure_count: 2,
  owner: 'ScaleSmall',
  repository_prefix: 'SSAI_Private_Fleet',
  allowed_no_history_evidence: [{
    repo: sensitiveMarkers[0],
    workflow: sensitiveMarkers[1],
    reason: sensitiveMarkers[8],
    workflow_source_sha256: sensitiveMarkers[9],
    witness: {
      workflow: sensitiveMarkers[2],
      run_id: 987654321012345,
      url: sensitiveMarkers[4],
      head_sha: sensitiveMarkers[6],
      event: 'push',
      head_repository: sensitiveMarkers[0],
    },
  }],
  authorized_disabled_workflow_hold_evidence: [{
    repository: sensitiveMarkers[0],
    workflow: sensitiveMarkers[1],
    workflow_id: 299211649,
    workflow_path: '.github/workflows/production-service-canaries.yml',
    workflow_state: 'disabled_manually',
    workflow_source_sha256: sensitiveMarkers[9],
    reason: sensitiveMarkers[8],
    recovery_evidence: false,
  }],
  recent_failure_recoveries: {
    workflows: [{ id: 987654321012345, name: sensitiveMarkers[1], head_sha: sensitiveMarkers[6] }],
    checks: [{ id: 987654321012345, name: sensitiveMarkers[2] }],
    statuses: [{ id: 987654321012345, context: sensitiveMarkers[2] }],
    deployments: [{ id: 987654321012345, environment: sensitiveMarkers[3] }],
  },
  failures: [{
    repo: sensitiveMarkers[0],
    owner: sensitiveMarkers[1],
    problem: sensitiveMarkers[7],
    url: sensitiveMarkers[4],
    incident_key: { repo: sensitiveMarkers[0], type: 'workflow-run', run_id: 987654321012345 },
  }],
  warnings: ['private no-history witness detail'],
  incident_fingerprint: sensitiveMarkers[9],
  previous_incident_source_run_id: 876543210123456,
};
const hostedStdout = JSON.stringify(releaseHealthLogPayload(adversarialHostedResult, hostedPublicEnvironment));
const hostedStepSummary = renderReleaseHealthStepSummary(adversarialHostedResult, hostedPublicEnvironment);
for (const marker of sensitiveMarkers) {
  assert.equal(hostedStdout.includes(marker), false, 'hosted stdout must redact sensitive marker: ' + marker);
  assert.equal(hostedStepSummary.includes(marker), false, 'hosted step summary must redact sensitive marker: ' + marker);
}
assert.deepEqual(
  releaseHealthLogPayload(adversarialHostedResult, hostedPublicEnvironment),
  {
    result: 'degraded',
    inventory_complete: true,
    notification_outcome: 'new-or-worsened-incident',
  },
  'hosted output must contain only the three coarse public fields',
);
const localStepSummary = renderReleaseHealthStepSummary(adversarialHostedResult, {});
assert.match(localStepSummary, /Authorized disabled workflow holds: 1/);
assert.match(localStepSummary, /Recovery evidence: `no`\./);
assert.equal(
  hostedStepSummary,
  '# Scale Small AI release health\n\n- Result: degraded\n- Inventory complete: yes\n- Notification outcome: new-or-worsened-incident\n',
  'hosted step summary must contain only coarse public health enums',
);
for (const forbiddenField of [
  'repositories', 'active_workflows', 'green_workflows', 'pending_workflows', 'failed_workflows',
  'allowed_no_history_workflows', 'unresolved_no_history_workflows', 'current_commit_checks',
  'github_api_requests', 'github_api_retries', 'failure_count', 'warning_count', 'incident_failure_count',
  'recent_failure_recoveries', 'failures', 'warnings', 'scan_mode', 'lookback_hours',
]) {
  assert.equal(hostedStdout.includes(forbiddenField), false, 'hosted stdout must omit count/detail field: ' + forbiddenField);
  assert.equal(hostedStepSummary.includes(forbiddenField), false, 'hosted step summary must omit count/detail field: ' + forbiddenField);
}
assert.match(hostedStepSummary, /Notification outcome: new-or-worsened-incident/);
assert.deepEqual(
  releaseHealthLogPayload(
    { ...adversarialHostedResult, notification_outcome: 'incident-improved-suppressed' },
    hostedPublicEnvironment,
  ),
  {
    result: 'degraded',
    inventory_complete: true,
    notification_outcome: 'incident-improved-suppressed',
  },
  'hosted output must expose the coarse improvement enum without private incident detail',
);

const renamedHostedEnvironment = {
  GITHUB_ACTIONS: 'TRUE',
  GITHUB_REPOSITORY: 'TransferredOrg/RenamedPublicMonitor',
  SSAI_RELEASE_MONITOR_FULL_OUTPUT: 'true',
  DEBUG: '1',
};
assert.deepEqual(
  releaseHealthLogPayload(adversarialHostedResult, renamedHostedEnvironment),
  releaseHealthLogPayload(adversarialHostedResult, hostedPublicEnvironment),
  'every hosted Actions repository must remain coarse-redacted across rename/transfer and debug flags',
);
for (const marker of sensitiveMarkers) {
  assert.equal(
    renderReleaseHealthStepSummary(adversarialHostedResult, renamedHostedEnvironment).includes(marker),
    false,
    'renamed hosted repository summary must redact sensitive marker: ' + marker,
  );
}

const injectedExceptionMarker = 'SSAI_Private_Fleet injected source error at https://private.invalid/run/987654321012345';
const hostedErrors = [];
const hostedExitCodes = [];
await executeReleaseHealthMonitorEntryPoint(
  async () => { throw new Error(injectedExceptionMarker); },
  {
    environment: hostedPublicEnvironment,
    error: (message) => hostedErrors.push(String(message)),
    setExitCode: (code) => hostedExitCodes.push(code),
  },
);
assert.deepEqual(hostedExitCodes, [1], 'hosted exceptions must fail closed');
assert.equal(hostedErrors.join('\n').includes(injectedExceptionMarker), false, 'hosted exception output must redact the raw error and stack');
assert.deepEqual(hostedErrors, ['::error::Release-health monitor failed closed before aggregate reporting.']);

const renamedHostedErrors = [];
await executeReleaseHealthMonitorEntryPoint(
  async () => { throw new Error(injectedExceptionMarker); },
  {
    environment: renamedHostedEnvironment,
    error: (message) => renamedHostedErrors.push(String(message)),
    setExitCode: () => {},
  },
);
assert.deepEqual(
  renamedHostedErrors,
  ['::error::Release-health monitor failed closed before aggregate reporting.'],
  'renamed/transferred hosted repositories must retain generic fail-closed exception output',
);

const localErrors = [];
await executeReleaseHealthMonitorEntryPoint(
  async () => { throw new Error(injectedExceptionMarker); },
  {
    environment: {},
    error: (message) => localErrors.push(String(message)),
    setExitCode: () => {},
  },
);
assert.equal(localErrors.join('\n').includes(injectedExceptionMarker), true, 'local diagnostics may retain the original exception');

const firstA = evaluateIncidentNotification('continuous', 'schedule', null, [incidentFailureA]);
assert.deepEqual(
  { changed: firstA.changed, suppressed: firstA.suppressed },
  { changed: true, suppressed: false },
  'the first A incident must fail and save state',
);
const repeatedA = evaluateIncidentNotification('continuous', 'schedule', firstA.current, [incidentFailureA]);
assert.deepEqual(
  { changed: repeatedA.changed, suppressed: repeatedA.suppressed },
  { changed: false, suppressed: true },
  'an unchanged scheduled A incident must be suppressed',
);
const sameEpisodeNewAttemptA = evaluateIncidentNotification(
  'continuous',
  'schedule',
  firstA.current,
  [{ ...incidentFailureA, incident_key: { ...incidentFailureA.incident_key, run_id: 101 } }],
);
assert.deepEqual(
  { changed: sameEpisodeNewAttemptA.changed, suppressed: sameEpisodeNewAttemptA.suppressed },
  { changed: false, suppressed: true },
  'new failing attempts in the same uninterrupted failure episode must remain suppressed',
);
const postSuccessRecurrenceA = evaluateIncidentNotification(
  'continuous',
  'schedule',
  firstA.current,
  [{
    ...incidentFailureA,
    incident_key: { ...incidentFailureA.incident_key, run_id: 102 },
    notification_key: { ...incidentFailureA.notification_key, episode_anchor: 'workflow-run:99:attempt:1' },
  }],
);
assert.deepEqual(
  { changed: postSuccessRecurrenceA.changed, suppressed: postSuccessRecurrenceA.suppressed },
  { changed: true, suppressed: false },
  'fail-success-fail recurrence must surface as a new episode even when both snapshots are incidents',
);
const worsenedAB = evaluateIncidentNotification('continuous', 'schedule', firstA.current, [incidentFailureA, incidentFailureB]);
assert.deepEqual(
  { changed: worsenedAB.changed, suppressed: worsenedAB.suppressed },
  { changed: true, suppressed: false },
  'A+B must surface and save as a worsened incident',
);
const partialRecoveryA = evaluateIncidentNotification('continuous', 'schedule', worsenedAB.current, [incidentFailureA]);
assert.deepEqual(
  { changed: partialRecoveryA.changed, improved: partialRecoveryA.improved, suppressed: partialRecoveryA.suppressed },
  { changed: true, improved: true, suppressed: true },
  'removal-only partial recovery must save the improved state without producing another red run',
);
const replacedB = {
  ...incidentFailureB,
  notification_key: { ...incidentFailureB.notification_key, failure_class: 'timed_out' },
};
const equalCountReplacement = evaluateIncidentNotification(
  'continuous',
  'schedule',
  worsenedAB.current,
  [incidentFailureA, replacedB],
);
assert.deepEqual(
  {
    changed: equalCountReplacement.changed,
    improved: equalCountReplacement.improved,
    suppressed: equalCountReplacement.suppressed,
  },
  { changed: true, improved: false, suppressed: false },
  'an equal-count cluster replacement must remain a red regression',
);
const mixedRemovalAndAddition = evaluateIncidentNotification(
  'continuous',
  'schedule',
  worsenedAB.current,
  [replacedB],
);
assert.deepEqual(
  {
    changed: mixedRemovalAndAddition.changed,
    improved: mixedRemovalAndAddition.improved,
    suppressed: mixedRemovalAndAddition.suppressed,
  },
  { changed: true, improved: false, suppressed: false },
  'a lower-count incident containing a new cluster must remain a red regression',
);
const cleanAfterA = evaluateIncidentNotification('continuous', 'schedule', partialRecoveryA.current, []);
assert.deepEqual(
  { changed: cleanAfterA.changed, suppressed: cleanAfterA.suppressed },
  { changed: true, suppressed: false },
  'clean health must save a recovery barrier',
);
const recurrenceA = evaluateIncidentNotification('continuous', 'schedule', cleanAfterA.current, [incidentFailureA]);
assert.deepEqual(
  { changed: recurrenceA.changed, suppressed: recurrenceA.suppressed },
  { changed: true, suppressed: false },
  'A recurring after a clean state must surface as a new incident',
);
for (const mode of ['continuous', 'incident']) {
  const manual = evaluateIncidentNotification(mode, 'workflow_dispatch', firstA.current, [incidentFailureA]);
  assert.equal(manual.enabled, false, 'manual ' + mode + ' scans must not enable deduplication');
  assert.equal(manual.suppressed, false, 'manual ' + mode + ' scans must remain fail-closed');
}
assert.equal(scheduledIncidentStateEnabled('incident', 'schedule'), false, 'incident scans must never deduplicate');

const selfMonitorDeployment = {
  deployment_id: 7001,
  id: 7002,
  state: 'failure',
  environment: 'release-health-monitor',
  task: 'deploy',
  identity_source: 'github-actions-job',
  source_workflow_id: 315630665,
  source_run_id: 29799900001,
  source_check_run_id: 88999000001,
  source_head_repository: 'ScaleSmall/SSAI_Shared',
  source_head_branch: 'main',
  source_event: 'schedule',
  source_check_name: 'Verify current organization release health',
  source_run_display_title: 'Release health monitor [continuous:6h]',
};
assert.equal(
  isExactSelfMonitorEnvironmentDeployment('SSAI_Shared', selfMonitorDeployment, 'main'),
  true,
  'the first failed exact monitor-environment deployment must be recognized as self-generated',
);
assert.equal(
  [selfMonitorDeployment, {
    ...selfMonitorDeployment,
    deployment_id: 7003,
    id: 7004,
    source_run_id: 29799900002,
    source_check_run_id: 88999000002,
  }].filter((status) => !isExactSelfMonitorEnvironmentDeployment('SSAI_Shared', status, 'main')).length,
  0,
  'the next scheduled scan must not turn exact self-generated environment deployments into a failure loop',
);
assert.equal(
  isExactSelfMonitorEnvironmentDeployment(
    'SSAI_Shared',
    { ...selfMonitorDeployment, source_workflow_id: 999 },
    'main',
  ),
  false,
  'a lookalike deployment from another workflow must remain in health inventory',
);

const stateContext = {
  repositoryId: 123,
  repository: 'ScaleSmall/SSAI_Shared',
  workflowRef: 'ScaleSmall/SSAI_Shared/.github/workflows/release-health-monitor.yml@refs/heads/main',
  ref: 'refs/heads/main',
  cachePrefix: 'ssai-release-health-state-v4-v1-',
  previousCachePrefix: 'ssai-release-health-state-v3-v1-',
  legacyCachePrefix: 'ssai-release-health-state-v2-v1-',
  hmacEpoch: 'v1',
};
const stateAuthenticationKey = 'state-hmac-key-'.repeat(4);
const laterIncidentDeliveryIdentity = 'run-30264003710-attempt-1';
const worsenedIncidentDeliveryIdentity = 'run-30264003711-attempt-1';
const stateRecord = createScheduledIncidentStateRecord(
  fingerprintA,
  stateContext,
  stateAuthenticationKey,
  '2026-07-21T18:00:00.000Z',
  incidentDeliveryIdentity,
);
const stateBytes = Buffer.from(JSON.stringify(stateRecord, null, 2) + '\n');
const stateKey = stateContext.cachePrefix + 'at-2026-07-21T18-00-00-000Z';
assert.equal(
  decodeScheduledIncidentState(stateBytes, stateKey, stateContext, stateAuthenticationKey).notificationStateHmac,
  notificationStateHmac(fingerprintA, stateAuthenticationKey, '2026-07-21T18:00:00.000Z'),
  'valid authenticated state must restore exactly',
);
assert.equal(
  decodeScheduledIncidentState(stateBytes, stateKey, stateContext, stateAuthenticationKey).notificationStateHmac,
  notificationStateHmac(fingerprintA, stateAuthenticationKey, '2026-07-21T18:00:00.000Z'),
  'rotating the independent read PAT cannot invalidate state authenticated by the dedicated HMAC key',
);
const laterStateRecord = createScheduledIncidentStateRecord(
  fingerprintA,
  stateContext,
  stateAuthenticationKey,
  '2026-07-21T18:01:00.000Z',
  laterIncidentDeliveryIdentity,
);
assert.equal(
  decodeScheduledIncidentState(stateBytes, stateKey, stateContext, stateAuthenticationKey)
    .incidentDeliveryIdentity,
  incidentDeliveryIdentity,
  'valid authenticated state must restore its stable non-sensitive delivery identity',
);
const previousStateUnsigned = {
  schema: 3,
  repository_id: stateContext.repositoryId,
  repository: stateContext.repository,
  workflow_ref: stateContext.workflowRef,
  ref: stateContext.ref,
  notification_state_hmac_sha256: stateRecord.notification_state_hmac_sha256,
  notification_cluster_hmac_tokens: stateRecord.notification_cluster_hmac_tokens,
  state_hmac_epoch: stateContext.hmacEpoch,
  created_at: stateRecord.created_at,
  scan_mode: 'continuous',
  trigger_event: 'schedule',
};
const previousStateRecord = {
  ...previousStateUnsigned,
  state_hmac_sha256: createHmac('sha256', stateAuthenticationKey)
    .update('release-health-state-record-v1\n' + JSON.stringify(previousStateUnsigned))
    .digest('hex'),
};
const previousStateKey = stateContext.previousCachePrefix + 'at-'
  + stateRecord.created_at.replace(/[:.]/g, '-');
const previousState = decodeScheduledIncidentState(
  Buffer.from(JSON.stringify(previousStateRecord) + '\n'),
  previousStateKey,
  stateContext,
  stateAuthenticationKey,
);
assert.equal(previousState.notificationStateHmac, stateRecord.notification_state_hmac_sha256);
assert.deepEqual(previousState.notificationClusterTokens, stateRecord.notification_cluster_hmac_tokens);
assert.equal(previousState.incidentDeliveryIdentity, null);
const exactPreviousMigration = evaluateIncidentNotification(
  'continuous',
  'schedule',
  previousState,
  [incidentFailureA],
  stateAuthenticationKey,
);
assert.deepEqual(
  {
    changed: exactPreviousMigration.changed,
    improved: exactPreviousMigration.improved,
    suppressed: exactPreviousMigration.suppressed,
    stateWriteRequired: exactPreviousMigration.stateWriteRequired,
  },
  { changed: false, improved: false, suppressed: true, stateWriteRequired: true },
  'an exact authenticated v3 state must migrate to v4 without producing another red run',
);
assert.equal(
  decodeScheduledIncidentState(
    Buffer.from(JSON.stringify(laterStateRecord) + '\n'),
    stateContext.cachePrefix + 'at-' + laterStateRecord.created_at.replace(/[:.]/g, '-'),
    stateContext,
    stateAuthenticationKey,
  ).incidentDeliveryIdentity,
  laterIncidentDeliveryIdentity,
  'the v4 rewrite must authenticate and restore the fresh delivery identity',
);
assert.notEqual(
  laterStateRecord.notification_state_hmac_sha256,
  stateRecord.notification_state_hmac_sha256,
  'opaque notification state HMACs must be salted per cache generation to prevent cross-cache linkability',
);
assert.equal(
  laterStateRecord.notification_cluster_hmac_tokens.some((token) => (
    stateRecord.notification_cluster_hmac_tokens.includes(token)
  )),
  false,
  'real and padded opaque cluster tokens must not be linkable across cache generations',
);
const opaqueRepeatedIncident = evaluateIncidentNotification(
  'continuous',
  'schedule',
  decodeScheduledIncidentState(stateBytes, stateKey, stateContext, stateAuthenticationKey),
  [incidentFailureA],
  stateAuthenticationKey,
);
assert.deepEqual(
  { changed: opaqueRepeatedIncident.changed, suppressed: opaqueRepeatedIncident.suppressed },
  { changed: false, suppressed: true },
  'an authenticated opaque state token must suppress only the exact unchanged incident',
);
const worsenedStateRecord = createScheduledIncidentStateRecord(
  fingerprintAB,
  stateContext,
  stateAuthenticationKey,
  '2026-07-21T18:05:00.000Z',
  worsenedIncidentDeliveryIdentity,
);
const worsenedStateBytes = Buffer.from(JSON.stringify(worsenedStateRecord, null, 2) + '\n');
const worsenedStateKey = stateContext.cachePrefix + 'at-2026-07-21T18-05-00-000Z';
const opaquePartialRecovery = evaluateIncidentNotification(
  'continuous',
  'schedule',
  decodeScheduledIncidentState(worsenedStateBytes, worsenedStateKey, stateContext, stateAuthenticationKey),
  [incidentFailureA],
  stateAuthenticationKey,
);
assert.deepEqual(
  {
    changed: opaquePartialRecovery.changed,
    improved: opaquePartialRecovery.improved,
    suppressed: opaquePartialRecovery.suppressed,
  },
  { changed: true, improved: true, suppressed: true },
  'authenticated opaque cluster tokens must recognize and suppress removal-only improvement',
);
const opaqueMixedChange = evaluateIncidentNotification(
  'continuous',
  'schedule',
  decodeScheduledIncidentState(worsenedStateBytes, worsenedStateKey, stateContext, stateAuthenticationKey),
  [replacedB],
  stateAuthenticationKey,
);
assert.deepEqual(
  {
    changed: opaqueMixedChange.changed,
    improved: opaqueMixedChange.improved,
    suppressed: opaqueMixedChange.suppressed,
  },
  { changed: true, improved: false, suppressed: false },
  'authenticated opaque cluster tokens must fail closed when a removal is mixed with an addition',
);
const legacyCreatedAt = '2026-07-21T17:55:00.000Z';
const legacyUnsignedState = {
  schema: 2,
  repository_id: stateContext.repositoryId,
  repository: stateContext.repository,
  workflow_ref: stateContext.workflowRef,
  ref: stateContext.ref,
  notification_state_hmac_sha256: notificationStateHmac(fingerprintA, stateAuthenticationKey),
  state_hmac_epoch: stateContext.hmacEpoch,
  created_at: legacyCreatedAt,
  scan_mode: 'continuous',
  trigger_event: 'schedule',
};
const legacyStateRecord = {
  ...legacyUnsignedState,
  state_hmac_sha256: createHmac('sha256', stateAuthenticationKey)
    .update('release-health-state-record-v1\n' + JSON.stringify(legacyUnsignedState))
    .digest('hex'),
};
const legacyStateKey = stateContext.legacyCachePrefix + 'at-' + legacyCreatedAt.replace(/[:.]/g, '-');
const legacyState = decodeScheduledIncidentState(
  Buffer.from(JSON.stringify(legacyStateRecord) + '\n'),
  legacyStateKey,
  stateContext,
  stateAuthenticationKey,
);
const exactLegacyMigration = evaluateIncidentNotification(
  'continuous',
  'schedule',
  legacyState,
  [incidentFailureA],
  stateAuthenticationKey,
);
assert.deepEqual(
  {
    changed: exactLegacyMigration.changed,
    improved: exactLegacyMigration.improved,
    suppressed: exactLegacyMigration.suppressed,
    stateWriteRequired: exactLegacyMigration.stateWriteRequired,
  },
  { changed: false, improved: false, suppressed: true, stateWriteRequired: true },
  'an exact authenticated v2 state must migrate to v4 without producing another red run',
);
const changedLegacyMigration = evaluateIncidentNotification(
  'continuous',
  'schedule',
  legacyState,
  [incidentFailureA, incidentFailureB],
  stateAuthenticationKey,
);
assert.deepEqual(
  {
    changed: changedLegacyMigration.changed,
    improved: changedLegacyMigration.improved,
    suppressed: changedLegacyMigration.suppressed,
    stateWriteRequired: changedLegacyMigration.stateWriteRequired,
  },
  { changed: true, improved: false, suppressed: false, stateWriteRequired: true },
  'a changed v2 incident must remain fail-closed when its opaque state cannot prove a removal-only transition',
);
const confidentialClusterDigests = Array.from({ length: 73 }, (_, index) => (
  createHash('sha256').update('confidential-cluster-' + index).digest('hex')
)).sort();
const confidentialSnapshot = {
  status: 'incident',
  incidentFingerprint: createHash('sha256')
    .update('release-health-incident-clusters-v2\n' + confidentialClusterDigests.join('\n'))
    .digest('hex'),
  failureCount: 73,
  failureDigestSample: Array.from({ length: 16 }, () => '6'.repeat(64)),
  clusterDigests: confidentialClusterDigests,
};
const confidentialStateBytes = Buffer.from(JSON.stringify(createScheduledIncidentStateRecord(
  confidentialSnapshot,
  stateContext,
  stateAuthenticationKey,
  '2026-07-21T18:15:00.000Z',
  incidentDeliveryIdentity,
)));
const healthyStateBytes = Buffer.from(JSON.stringify(createScheduledIncidentStateRecord(
  fingerprintReleaseHealthIncident([]),
  stateContext,
  stateAuthenticationKey,
  '2026-07-21T18:15:00.000Z',
  incidentDeliveryIdentity,
)));
assert.equal(
  confidentialStateBytes.length,
  healthyStateBytes.length,
  'fork-visible cache state size must not reveal healthy versus incident state',
);
assert.equal(
  confidentialStateBytes.length < 192 * 1024,
  true,
  'fixed-size opaque cache state must remain inside its bounded write limit',
);
for (const privateStateMarker of [
  'incident', 'healthy', confidentialSnapshot.incidentFingerprint, confidentialSnapshot.failureDigestSample[0],
  confidentialSnapshot.clusterDigests[0], 'failure_count', 'failure_digest_sample', 'source_run_id', 'source_sha',
]) {
  assert.equal(
    confidentialStateBytes.includes(Buffer.from(privateStateMarker)),
    false,
    'fork-visible cache state must not contain private-derived marker: ' + privateStateMarker,
  );
}
assert.deepEqual(
  Object.keys(stateRecord).sort(),
  [
    'created_at', 'delivery_identity', 'notification_cluster_hmac_tokens', 'notification_state_hmac_sha256',
    'ref', 'repository', 'repository_id', 'scan_mode', 'schema', 'state_hmac_epoch', 'state_hmac_sha256',
    'trigger_event', 'workflow_ref',
  ],
  'cache state must have a fixed public-provenance plus padded opaque-HMAC shape',
);
assert.equal(
  stateRecord.notification_cluster_hmac_tokens.length,
  2048,
  'cache state must pad the opaque cluster token inventory to its fixed maximum',
);
assert.equal(
  new Set(stateRecord.notification_cluster_hmac_tokens).size,
  stateRecord.notification_cluster_hmac_tokens.length,
  'cache state cluster tokens and padding must be collision-free',
);
assert.throws(
  () => decodeScheduledIncidentState(null, stateKey, stateContext, stateAuthenticationKey),
  /bytes are missing/,
  'a matched cache key without a state file remains a hard I/O failure',
);
assert.equal(
  decodeScheduledIncidentStateOrNull(Buffer.from('{}\n'), stateKey, stateContext, stateAuthenticationKey),
  null,
  'corrupt restored state must safely reinitialize',
);
const malformedBytes = Buffer.from('{not-json}\n');
assert.equal(
  decodeScheduledIncidentStateOrNull(malformedBytes, stateKey, stateContext, stateAuthenticationKey),
  null,
  'malformed restored JSON must safely reinitialize',
);
assert.equal(
  decodeScheduledIncidentStateOrNull(
    Buffer.from(JSON.stringify({ ...stateRecord, schema: 999 }) + '\n'),
    stateKey,
    stateContext,
    stateAuthenticationKey,
  ),
  null,
  'wrong-schema restored state must safely reinitialize',
);
assert.equal(
  decodeScheduledIncidentStateOrNull(
    Buffer.from(JSON.stringify({
      ...stateRecord,
      notification_cluster_hmac_tokens: [
        '0'.repeat(64),
        ...stateRecord.notification_cluster_hmac_tokens.slice(1),
      ].sort(),
    }) + '\n'),
    stateKey,
    stateContext,
    stateAuthenticationKey,
  ),
  null,
  'tampered opaque cluster tokens must safely reinitialize instead of suppressing',
);
assert.equal(
  decodeScheduledIncidentStateOrNull(
    Buffer.from(JSON.stringify({
      ...stateRecord,
      delivery_identity: 'run-0-attempt-1',
    }) + '\n'),
    stateKey,
    stateContext,
    stateAuthenticationKey,
  ),
  null,
  'tampered or invalid delivery identity must safely reinitialize instead of suppressing reconciliation',
);
assert.equal(
  decodeScheduledIncidentStateOrNull(
    stateBytes,
    stateContext.cachePrefix + 'at-2026-07-21T18-00-00-001Z',
    stateContext,
    stateAuthenticationKey,
  ),
  null,
  'a cache-key timestamp mismatch must safely reinitialize',
);
assert.equal(
  decodeScheduledIncidentStateOrNull(stateBytes, stateKey, stateContext, 'rotated-hmac-key-'.repeat(4)),
  null,
  'HMAC-key rotation must safely reinitialize instead of suppressing',
);
assert.equal(
  decodeScheduledIncidentStateOrNull(stateBytes, stateKey, { ...stateContext, hmacEpoch: 'v2' }, stateAuthenticationKey),
  null,
  'HMAC epoch rotation must safely reinitialize instead of suppressing',
);
const reinitializedIncident = evaluateIncidentNotification('continuous', 'schedule', null, [incidentFailureA]);
assert.deepEqual(
  { changed: reinitializedIncident.changed, suppressed: reinitializedIncident.suppressed },
  { changed: true, suppressed: false },
  'reinitialized state must surface and persist the current incident once',
);

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
const continuousPageLimits = releaseHealthPageLimits('continuous');
const incidentPageLimits = releaseHealthPageLimits('incident');
const checkHeadSha = 'a'.repeat(40);
const checkRunFixture = (id, overrides = {}) => ({
  id,
  head_sha: checkHeadSha,
  name: `check-${id}`,
  status: 'completed',
  conclusion: 'success',
  started_at: '2026-08-09T12:00:00Z',
  completed_at: '2026-08-09T12:01:00Z',
  pull_requests: [],
  ...overrides,
});
const checkRunPageContext = ({
  seenCheckRunIds = new Set(),
  priorTotalCount = null,
  accumulatedCount = 0,
  page = 1,
  pageLimit = continuousPageLimits.checks,
} = {}) => ({
  expectedHeadSha: checkHeadSha,
  seenCheckRunIds,
  priorTotalCount,
  accumulatedCount,
  page,
  pageLimit,
});
assert.equal(continuousPageLimits.checks, 50, 'continuous scans must retain a bounded multi-week long-lived-head check-run window');
assert.equal(incidentPageLimits.checks, 50, 'incident scans must preserve at least the continuous check-run page bound');
for (const { filter, checkRunCount } of [
  { filter: 'latest', checkRunCount: 1012 },
  { filter: 'all', checkRunCount: 1013 },
]) {
  const pageCount = Math.ceil(checkRunCount / 100);
  let totalCount = null;
  let accumulatedCount = 0;
  const seenCheckRunIds = new Set();
  for (let page = 1; page <= pageCount; page += 1) {
    const remaining = checkRunCount - ((page - 1) * 100);
    const batchSize = Math.min(100, remaining);
    const firstId = ((page - 1) * 100) + 1;
    const expected = page === pageCount ? 'complete' : 'continue';
    const validated = validateReleaseHealthCheckRunPage(
      {
        total_count: checkRunCount,
        check_runs: Array.from({ length: batchSize }, (_, offset) => checkRunFixture(firstId + offset)),
      },
      checkRunPageContext({ seenCheckRunIds, priorTotalCount: totalCount, accumulatedCount, page }),
    );
    assert.equal(
      validated.disposition,
      expected,
      `continuous ${filter} check pagination must cover the observed post-rollout ${checkRunCount}-run long-lived-head case`,
    );
    totalCount = validated.totalCount;
    accumulatedCount += validated.checkRuns.length;
    for (const id of validated.checkRunIds) seenCheckRunIds.add(id);
  }
  assert.equal(accumulatedCount, checkRunCount, `${filter} check pagination must cover every declared check run`);
  assert.equal(seenCheckRunIds.size, checkRunCount, `${filter} check pagination must cover distinct check-run identities`);
}
const fullFiftiethPageSeenIds = new Set(Array.from({ length: 4900 }, (_, offset) => offset + 1));
const fullFifthPageSeenIds = new Set(Array.from({ length: 400 }, (_, offset) => offset + 1));
assert.equal(
  validateReleaseHealthCheckRunPage(
    {
      total_count: 500,
      check_runs: Array.from({ length: 100 }, (_, offset) => checkRunFixture(401 + offset)),
    },
    checkRunPageContext({
      seenCheckRunIds: fullFifthPageSeenIds,
      priorTotalCount: 500,
      accumulatedCount: 400,
      page: 5,
    }),
  ).disposition,
  'complete',
  'a full page below the cap must complete when stable total_count proves the exact 500-record boundary',
);
assert.equal(
  validateReleaseHealthCheckRunPage(
    {
      total_count: 5000,
      check_runs: Array.from({ length: 100 }, (_, offset) => checkRunFixture(4901 + offset)),
    },
    checkRunPageContext({
      seenCheckRunIds: fullFiftiethPageSeenIds,
      priorTotalCount: 5000,
      accumulatedCount: 4900,
      page: 50,
    }),
  ).disposition,
  'truncated',
  'a full page at the configured 5000-record safety cap must remain fail-closed even when total_count matches',
);
assert.equal(
  validateReleaseHealthCheckRunPage(
    {
      total_count: 5001,
      check_runs: Array.from({ length: 100 }, (_, offset) => checkRunFixture(4901 + offset)),
    },
    checkRunPageContext({
      seenCheckRunIds: fullFiftiethPageSeenIds,
      priorTotalCount: 5001,
      accumulatedCount: 4900,
      page: 50,
    }),
  ).disposition,
  'truncated',
  'a full fiftieth page must remain fail-closed when stable total_count proves another record exists',
);
assert.throws(
  () => releaseHealthCheckPageDisposition(51, 1, continuousPageLimits.checks),
  /check pagination input is invalid/,
);

{
  const started = [];
  await assert.rejects(
    mapLimit([0, 1, 2, 3, 4, 5], 2, async (value) => {
      started.push(value);
      if (value === 0) throw new Error('first worker failed');
      await new Promise((resolve) => setTimeout(resolve, 5));
      return value;
    }),
    /first worker failed/,
  );
  assert.deepEqual(
    started,
    [0, 1],
    'a fatal worker error must stop mapLimit from dequeuing more API-producing work',
  );
}
for (const malformedCheckPage of [
  null,
  [],
  {},
  { total_count: 1 },
  { total_count: 1, check_runs: null },
  { total_count: 1, check_runs: {} },
]) {
  assert.throws(
    () => validateReleaseHealthCheckRunPage(malformedCheckPage, checkRunPageContext()),
    /check-run page returned an invalid response/,
  );
}
const validActiveChecks = validateReleaseHealthCheckRunPage(
  {
    total_count: 5,
    check_runs: [
      checkRunFixture(1, {
        status: 'queued',
        conclusion: null,
        started_at: null,
        completed_at: null,
      }),
      checkRunFixture(2, {
        status: 'in_progress',
        conclusion: null,
        completed_at: null,
      }),
      ...['waiting', 'requested', 'pending'].map((status, offset) => checkRunFixture(3 + offset, {
        status,
        conclusion: null,
        started_at: null,
        completed_at: null,
      })),
    ],
  },
  checkRunPageContext(),
);
assert.equal(validActiveChecks.disposition, 'complete', 'all five active check-run statuses must remain classifiable');
assert.deepEqual(validActiveChecks.checkRunIds, [1, 2, 3, 4, 5], 'all five active check-run statuses must retain their validated identities');
const activeCheckNowMs = Date.parse('2026-08-09T12:30:00Z');
const freshSourceRunActivityAt = releaseHealthCheckSourceActivityFallback(
  validActiveChecks.checkRuns[0],
  { run_started_at: '2026-08-09T12:25:00Z', created_at: '2026-08-09T12:20:00Z' },
);
assert.equal(freshSourceRunActivityAt, '2026-08-09T12:25:00Z', 'a source-run start must provide the preferred pre-start age fallback');
assert.equal(
  releaseHealthActiveCheckDisposition(
    { ...validActiveChecks.checkRuns[0], run_started_at: freshSourceRunActivityAt },
    activeCheckNowMs,
    45 * 60 * 1000,
  ),
  'pending',
  'a fresh pre-start current check must remain pending instead of becoming instant-stuck',
);
const oldSourceRunActivityAt = releaseHealthCheckSourceActivityFallback(
  validActiveChecks.checkRuns[0],
  { run_started_at: null, created_at: '2026-08-09T10:00:00Z' },
);
assert.equal(oldSourceRunActivityAt, '2026-08-09T10:00:00Z', 'source-run creation must backstop a missing source-run start');
assert.equal(
  releaseHealthCheckSourceActivityFallback(
    { ...validActiveChecks.checkRuns[0], created_at: '2030-01-01T00:00:00Z', updated_at: '2030-01-01T00:00:00Z' },
    { run_started_at: null, created_at: '2026-08-09T10:00:00Z' },
  ),
  '2026-08-09T10:00:00Z',
  'non-schema raw check timestamps must not suppress authoritative source-run age evidence',
);
assert.equal(
  releaseHealthActiveCheckDisposition(
    { ...validActiveChecks.checkRuns[0], run_started_at: oldSourceRunActivityAt },
    activeCheckNowMs,
    45 * 60 * 1000,
  ),
  'stuck',
  'an old pre-start check must become stuck from its associated source-run age evidence',
);
assert.equal(
  releaseHealthActiveCheckDisposition(validActiveChecks.checkRuns[0], activeCheckNowMs, 45 * 60 * 1000),
  'unageable',
  'a schema-valid pre-start check without age evidence must fail its age attestation instead of remaining pending forever',
);
const oldStartRecentActivityCheck = validActiveChecks.checkRuns[0];
const oldStartAt = releaseHealthCheckSourceActivityFallback(
  oldStartRecentActivityCheck,
  { run_started_at: '2026-08-09T10:00:00Z', created_at: '2026-08-09T09:59:00Z', updated_at: '2026-08-09T12:25:00Z' },
);
const recentActivityAt = releaseHealthCheckSourceRecentActivityFallback(
  oldStartRecentActivityCheck,
  { run_started_at: '2026-08-09T10:00:00Z', created_at: '2026-08-09T09:59:00Z', updated_at: '2026-08-09T12:25:00Z' },
);
const oldStartRecentActivityEnriched = {
  ...oldStartRecentActivityCheck,
  run_started_at: oldStartAt,
  created_at: null,
  updated_at: null,
  source_run_activity_at: recentActivityAt,
};
assert.equal(oldStartAt, '2026-08-09T10:00:00Z', 'source occurrence must stay bound to the old run start');
assert.equal(recentActivityAt, '2026-08-09T12:25:00Z', 'source recent activity must use the later run update');
assert.equal(releaseHealthCheckRecentActivityTime(oldStartRecentActivityEnriched), Date.parse(recentActivityAt), 'recent filtering must retain a check completed or updated inside the lookback');
assert.equal(recordOccurrenceTime(oldStartRecentActivityEnriched), Date.parse(oldStartAt), 'recent source activity must not move the check occurrence');
assert.equal(
  releaseHealthActiveCheckDisposition(oldStartRecentActivityEnriched, activeCheckNowMs, 45 * 60 * 1000),
  'stuck',
  'stuck age must remain bound to the old run occurrence rather than its recent update',
);
const completedOldStart = checkRunFixture(20, {
  started_at: '2026-08-09T04:00:00Z',
  completed_at: null,
});
const completedOldStartRecentSourceUpdate = releaseHealthCheckSourceRecentActivityFallback(
  completedOldStart,
  { run_started_at: '2026-08-09T04:00:00Z', created_at: '2026-08-09T03:59:00Z', updated_at: '2026-08-09T12:25:00Z' },
);
assert.equal(
  completedOldStartRecentSourceUpdate,
  '2026-08-09T12:25:00Z',
  'a completed check with old start and null completion must retain a later trusted source-run update',
);
assert.equal(
  releaseHealthCheckRecentActivityTime({
    ...completedOldStart,
    run_started_at: null,
    created_at: null,
    updated_at: null,
    source_run_activity_at: completedOldStartRecentSourceUpdate,
  }),
  Date.parse(completedOldStartRecentSourceUpdate),
  'post-enrichment lookback filtering must use the later source update instead of dropping the check at its old start',
);
const completedNullStartOldCompletion = checkRunFixture(21, {
  started_at: null,
  completed_at: '2026-08-09T04:00:00Z',
});
const completedNullStartRecentSourceUpdate = releaseHealthCheckSourceRecentActivityFallback(
  completedNullStartOldCompletion,
  { run_started_at: null, created_at: '2026-08-09T03:59:00Z', updated_at: '2026-08-09T12:25:00Z' },
);
const completedNullStartEnriched = {
  ...completedNullStartOldCompletion,
  run_started_at: null,
  created_at: null,
  updated_at: null,
  source_run_activity_at: completedNullStartRecentSourceUpdate,
};
assert.equal(
  recordOccurrenceTime(completedNullStartEnriched),
  Date.parse('2026-08-09T04:00:00Z'),
  'source recent activity must not move a completed check occurrence beyond its completion evidence',
);
assert.equal(
  releaseHealthCheckRecentActivityTime(completedNullStartEnriched),
  Date.parse('2026-08-09T12:25:00Z'),
  'source recent activity must independently retain an old completed check inside the lookback',
);
const githubActionsCheck = checkRunFixture(30, {
  app: { slug: 'github-actions' },
  details_url: 'https://github.com/ScaleSmall/SSAI_Test/actions/runs/123/job/456',
});
const matchingSourceRun = {
  id: 123,
  head_sha: checkHeadSha,
  repository: { full_name: 'ScaleSmall/SSAI_Test' },
};
assert.equal(
  validateReleaseHealthCheckSourceRun(githubActionsCheck, matchingSourceRun, 'ScaleSmall/SSAI_Test'),
  matchingSourceRun,
  'GitHub Actions source evidence must bind the exact run, commit, and repository',
);
assert.equal(
  validateReleaseHealthCheckSourceRun(
    { ...githubActionsCheck, app: { slug: 'external-ci' } },
    matchingSourceRun,
    'ScaleSmall/SSAI_Test',
  ),
  null,
  'a third-party check must not inherit GitHub Actions source-run provenance from a lookalike URL',
);
for (const mismatchedSourceRun of [
  { ...matchingSourceRun, id: 124 },
  { ...matchingSourceRun, id: '123' },
  { ...matchingSourceRun, head_sha: 'b'.repeat(40) },
  { ...matchingSourceRun, repository: { full_name: 'ScaleSmall/SSAI_Other' } },
]) {
  assert.throws(
    () => validateReleaseHealthCheckSourceRun(githubActionsCheck, mismatchedSourceRun, 'ScaleSmall/SSAI_Test'),
    /failed repository, commit, or identity binding/,
    'mismatched Actions source evidence must fail closed',
  );
}
const completedWithoutLifecycle = validateReleaseHealthCheckRunPage(
  {
    total_count: 1,
    check_runs: [checkRunFixture(10, {
      conclusion: 'failure',
      started_at: null,
      completed_at: null,
    })],
  },
  checkRunPageContext(),
);
assert.equal(completedWithoutLifecycle.disposition, 'complete', 'a completed check with schema-valid null lifecycle timestamps must remain classifiable');
assert.equal(
  releaseHealthActiveCheckDisposition(completedWithoutLifecycle.checkRuns[0], activeCheckNowMs, 45 * 60 * 1000),
  'completed',
  'a completed failure must remain completed even when its CheckRun lifecycle timestamps are null',
);
assert.equal(
  releaseHealthCheckSourceActivityFallback(
    completedWithoutLifecycle.checkRuns[0],
    { run_started_at: '2026-08-09T10:00:00Z', created_at: '2026-08-09T09:59:00Z' },
  ),
  '2026-08-09T10:00:00Z',
  'a completed check with null lifecycle timestamps must inherit source-run activity before recent filtering',
);
const noAgeFailureOne = completedWithoutLifecycle.checkRuns[0];
const noAgeFailureTwo = { ...noAgeFailureOne, id: 11 };
const noAgeAnchorOne = checkFailureEpisodeAnchor(noAgeFailureOne, [noAgeFailureOne]);
const noAgeAnchorTwo = checkFailureEpisodeAnchor(noAgeFailureTwo, [noAgeFailureTwo]);
assert.equal(noAgeAnchorOne, 'check-run:10');
assert.equal(noAgeAnchorTwo, 'check-run:11');
const noAgeFingerprint = (checkRun, episodeAnchor) => fingerprintReleaseHealthIncident([{
  incident_key: {
    repo: 'SSAI_Test',
    type: 'current-check-run',
    check_run_id: checkRun.id,
    conclusion: checkRun.conclusion,
  },
  notification_key: {
    repo: 'SSAI_Test',
    type: 'current-check-run',
    stream_sha256: 'f'.repeat(64),
    failure_class: checkRun.conclusion,
    episode_anchor: episodeAnchor,
  },
}]).incidentFingerprint;
assert.notEqual(
  noAgeFingerprint(noAgeFailureOne, noAgeAnchorOne),
  noAgeFingerprint(noAgeFailureTwo, noAgeAnchorTwo),
  'distinct completed no-age failures must not collapse into one suppressible incident fingerprint',
);
for (const malformedCheckRun of [
  null,
  {},
  checkRunFixture(1, { head_sha: 'b'.repeat(40) }),
  checkRunFixture(0),
  checkRunFixture('1'),
  checkRunFixture(1, { name: '' }),
  checkRunFixture(1, { name: ' check-1 ' }),
  checkRunFixture(1, { status: '' }),
  checkRunFixture(1, { status: 'unknown' }),
  checkRunFixture(1, { status: ' completed ' }),
  checkRunFixture(1, { status: 'in_progress', conclusion: 'success', completed_at: null }),
  checkRunFixture(1, { status: 'in_progress', conclusion: '', completed_at: null }),
  (() => {
    const missingConclusion = checkRunFixture(1, { status: 'in_progress', conclusion: null, completed_at: null });
    delete missingConclusion.conclusion;
    return missingConclusion;
  })(),
  checkRunFixture(1, { conclusion: ' failure ' }),
  checkRunFixture(1, { head_sha: ` ${checkHeadSha}` }),
  checkRunFixture(1, { status: 'queued', conclusion: null, started_at: 'not-a-timestamp', completed_at: null }),
  checkRunFixture(1, { status: 'queued', conclusion: null, started_at: '', completed_at: null }),
  checkRunFixture(1, { started_at: '2026-08-09T12:00:00Z', completed_at: '' }),
  checkRunFixture(1, { started_at: '', completed_at: '' }),
  checkRunFixture(1, { status: 'queued', conclusion: null, started_at: 'August 9, 2026 12:00 UTC', completed_at: null }),
  checkRunFixture(1, { status: 'queued', conclusion: null, started_at: '2026-02-30T12:00:00Z', completed_at: null }),
  checkRunFixture(1, { conclusion: null }),
  checkRunFixture(1, { pull_requests: null }),
]) {
  assert.throws(
    () => validateReleaseHealthCheckRunPage(
      { total_count: 1, check_runs: [malformedCheckRun] },
      checkRunPageContext(),
    ),
    /invalid check-run record/,
  );
}
assert.throws(
  () => validateReleaseHealthCheckRunPage(
    { total_count: 2, check_runs: [checkRunFixture(1), checkRunFixture(1)] },
    checkRunPageContext(),
  ),
  /duplicate check-run identity/,
);
assert.throws(
  () => validateReleaseHealthCheckRunPage(
    { total_count: 2, check_runs: [checkRunFixture(1)] },
    checkRunPageContext({
      seenCheckRunIds: new Set([1]),
      priorTotalCount: 2,
      accumulatedCount: 1,
      page: 2,
    }),
  ),
  /duplicate check-run identity/,
);
assert.throws(
  () => validateReleaseHealthCheckRunPage(
    {
      total_count: 509,
      check_runs: Array.from({ length: 100 }, (_, offset) => checkRunFixture(101 + offset)),
    },
    checkRunPageContext({
      seenCheckRunIds: new Set(Array.from({ length: 100 }, (_, offset) => offset + 1)),
      priorTotalCount: 508,
      accumulatedCount: 100,
      page: 2,
    }),
  ),
  /check-run total changed during pagination/,
);
assert.throws(
  () => validateReleaseHealthCheckRunPage(
    {
      total_count: 508,
      check_runs: Array.from({ length: 7 }, (_, offset) => checkRunFixture(501 + offset)),
    },
    checkRunPageContext({
      seenCheckRunIds: new Set(Array.from({ length: 500 }, (_, offset) => offset + 1)),
      priorTotalCount: 508,
      accumulatedCount: 500,
      page: 6,
    }),
  ),
  /check-run pagination ended before its declared total count/,
);
assert.throws(() => releaseHealthPageLimits('unbounded'), /page-limit mode is invalid/);
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

const authorizedDisabledHoldSource = 'name: Production Service Delivery Canaries\non:\n  workflow_dispatch:\n';
const authorizedDisabledHoldWorkflow = {
  id: 299211649,
  name: 'Production Service Delivery Canaries',
  path: '.github/workflows/production-service-canaries.yml',
  state: 'disabled_manually',
};
const authorizedDisabledHoldPolicy = {
  workflowId: authorizedDisabledHoldWorkflow.id,
  name: authorizedDisabledHoldWorkflow.name,
  path: authorizedDisabledHoldWorkflow.path,
  state: 'disabled_manually',
  sourceSha256: createHash('sha256').update(authorizedDisabledHoldSource).digest('hex'),
  headRepository: 'ScaleSmall/SSAI_Production_QA',
  reason: 'Explicitly held for a bounded protected activation.',
};
const authorizedDisabledHold = verifyAuthorizedDisabledWorkflowHold({
  workflow: authorizedDisabledHoldWorkflow,
  policy: authorizedDisabledHoldPolicy,
  workflowSource: authorizedDisabledHoldSource,
  repository: 'ScaleSmall/SSAI_Production_QA',
});
assert.ok(authorizedDisabledHold, 'the exact source-bound disabled workflow hold must verify');
assert.equal(authorizedDisabledHold.recoveryEvidence, false, 'an authorized disabled hold must never be recovery evidence');
assert.equal('recoveryEvents' in authorizedDisabledHold, false, 'a disabled hold must not expose a recovery-event contract');
assert.equal(isTrustedMonitorRecoveryPolicy(authorizedDisabledHold), false, 'a disabled hold must not enter trusted recovery');
for (const [label, workflowMutation = {}, policyMutation = {}, sourceMutation = authorizedDisabledHoldSource, repository = 'ScaleSmall/SSAI_Production_QA'] of [
  ['active state', { state: 'active' }],
  ['different disabled state', { state: 'disabled_inactivity' }],
  ['wrong workflow id', { id: 299211650 }],
  ['wrong workflow name', { name: 'Production Provider Webhook Canaries' }],
  ['wrong workflow path', { path: '.github/workflows/provider-webhook-canaries.yml' }],
  ['changed source', {}, {}, authorizedDisabledHoldSource + '# changed\n'],
  ['wrong repository', {}, {}, authorizedDisabledHoldSource, 'ScaleSmall/SSAI_Dashboard'],
  ['blank rationale', {}, { reason: '' }],
  ['recovery-capable policy', {}, { recoveryEvents: ['workflow_dispatch'] }],
]) {
  assert.equal(verifyAuthorizedDisabledWorkflowHold({
    workflow: { ...authorizedDisabledHoldWorkflow, ...workflowMutation },
    policy: { ...authorizedDisabledHoldPolicy, ...policyMutation },
    workflowSource: sourceMutation,
    repository,
  }), null, label + ' must invalidate the disabled workflow hold');
}
const unrelatedHeldWorkflowSuccess = {
  ...failedRun,
  id: 307,
  workflow_id: authorizedDisabledHoldWorkflow.id,
  status: 'completed',
  conclusion: 'success',
  created_at: '2026-07-18T10:05:00Z',
};
assert.equal(
  findSupersedingWorkflowRun(failedRun, [failedRun, unrelatedHeldWorkflowSuccess]),
  null,
  'an authorized hold on another workflow must not suppress an unrelated failure',
);

const forwardFixSource = 'name: Production n8n workflow exactness\non:\n  schedule:\n  workflow_dispatch:\n';
const forwardFixWorkflow = {
  id: 315750527,
  name: 'Production n8n workflow exactness',
  path: '.github/workflows/n8n-production-exactness.yml',
  state: 'active',
};
const forwardFixPolicyInput = {
  workflowId: forwardFixWorkflow.id,
  path: forwardFixWorkflow.path,
  sourceSha256: createHash('sha256').update(forwardFixSource).digest('hex'),
  headRepository: 'ScaleSmall/SSAI_PoW',
  failedEvents: ['schedule'],
  recoveryEvents: ['workflow_dispatch'],
  jobNames: ['verify-production'],
  recoveryDisplayTitles: ['Production n8n workflow exactness'],
};
const forwardFixPolicy = verifyForwardFixRecoveryPolicy({
  workflow: forwardFixWorkflow,
  workflowSource: forwardFixSource,
  policy: forwardFixPolicyInput,
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
const monitorCurrentDeliverySource = Buffer.from('export const delivery = true;\n', 'utf8');
const monitorVerificationContext = {
  currentHeadSha: monitorCurrentSha,
  monitorImplementationSource: {
    scriptSource: monitorCurrentScriptSource,
    utilsSource: monitorCurrentUtilsSource,
    deliverySource: monitorCurrentDeliverySource,
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
    deliverySourceSha256: null,
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
    deliverySourceSha256: null,
  }],
};
const auditedOriginSources = new Map([[monitorOldSha, {
  workflowSource: auditedHistoricalWorkflowSource,
  scriptSource: auditedHistoricalScriptSource,
  utilsSource: auditedHistoricalUtilsSource,
  deliverySource: null,
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
const controlledDisabledMonitorRun = {
  id: 799,
  run_attempt: 2,
  workflow_id: monitorWorkflow.id,
  head_branch: 'main',
  head_sha: monitorCurrentSha,
  head_repository: { full_name: 'ScaleSmall/SSAI_Shared' },
  event: 'workflow_dispatch',
  display_title: 'Release health monitor [incident:168h]',
  status: 'in_progress',
  conclusion: null,
};
const controlledDisabledMonitorContext = {
  currentRun: controlledDisabledMonitorRun,
  currentRunId: controlledDisabledMonitorRun.id,
  currentRunAttempt: controlledDisabledMonitorRun.run_attempt,
  currentRepository: 'ScaleSmall/SSAI_Shared',
  defaultBranch: 'main',
  scanMode: 'incident',
  lookbackHours: 168,
};
const disabledMonitorWorkflow = { ...monitorWorkflow, state: 'disabled_manually' };
assert.equal(isControlledDisabledMonitorRecoveryWorkflow({
  workflow: disabledMonitorWorkflow,
  policy: monitorPolicyInput,
  currentHeadSha: monitorCurrentSha,
  context: controlledDisabledMonitorContext,
}), true, 'the exact in-flight current-main incident run may retain policy verification after the runbook re-disables the monitor');
assert.ok(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: disabledMonitorWorkflow,
  workflowSource: monitorSource,
  policy: monitorPolicyInput,
  auditedOriginSources,
  controlledRunContext: controlledDisabledMonitorContext,
}), 'the exact controlled disabled monitor must preserve its source-verified recovery policy');
for (const [label, contextMutation, runMutation = {}] of [
  ['missing context', null],
  ['continuous scan', { scanMode: 'continuous' }],
  ['narrow scan', { lookbackHours: 167 }],
  ['wrong repository', { currentRepository: 'ScaleSmall/SSAI_Dashboard' }],
  ['wrong run id', { currentRunId: 798 }],
  ['wrong attempt', { currentRunAttempt: 1 }],
  ['missing context attempt', { currentRunAttempt: undefined }],
  ['zero context attempt', { currentRunAttempt: 0 }],
  ['wrong branch', {}, { head_branch: 'release' }],
  ['wrong head SHA', {}, { head_sha: monitorOldSha }],
  ['wrong head repository', {}, { head_repository: { full_name: 'fork/SSAI_Shared' } }],
  ['wrong workflow', {}, { workflow_id: 123 }],
  ['missing API attempt', {}, { run_attempt: undefined }],
  ['zero API attempt', {}, { run_attempt: 0 }],
  ['scheduled run', {}, { event: 'schedule' }],
  ['wrong run title', {}, { display_title: 'Release health monitor [continuous:6h]' }],
  ['queued run', {}, { status: 'queued' }],
  ['missing conclusion', {}, { conclusion: undefined }],
  ['empty conclusion', {}, { conclusion: '' }],
  ['completed run', {}, { status: 'completed', conclusion: 'success' }],
]) {
  const mutatedContext = contextMutation === null ? null : {
    ...controlledDisabledMonitorContext,
    ...contextMutation,
    currentRun: { ...controlledDisabledMonitorRun, ...runMutation },
  };
  assert.equal(isControlledDisabledMonitorRecoveryWorkflow({
    workflow: disabledMonitorWorkflow,
    policy: monitorPolicyInput,
    currentHeadSha: monitorCurrentSha,
    context: mutatedContext,
  }), false, label + ' must not authorize a disabled monitor recovery policy');
  assert.equal(verifyForwardFixRecoveryPolicy({
    ...monitorVerificationContext,
    workflow: disabledMonitorWorkflow,
    workflowSource: monitorSource,
    policy: monitorPolicyInput,
    auditedOriginSources,
    controlledRunContext: mutatedContext,
  }), null, label + ' must fail closed during disabled monitor policy verification');
}
assert.equal(isControlledDisabledMonitorRecoveryWorkflow({
  workflow: { ...disabledMonitorWorkflow, state: 'disabled_inactivity' },
  policy: monitorPolicyInput,
  currentHeadSha: monitorCurrentSha,
  context: controlledDisabledMonitorContext,
}), false, 'only the runbook-controlled disabled_manually state may retain policy verification');
assert.equal(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: { ...disabledMonitorWorkflow, state: 'disabled_inactivity' },
  workflowSource: monitorSource,
  policy: monitorPolicyInput,
  auditedOriginSources,
  controlledRunContext: controlledDisabledMonitorContext,
}), null, 'a different disabled state must fail closed');
assert.equal(verifyForwardFixRecoveryPolicy({
  workflow: { ...forwardFixWorkflow, state: 'disabled_manually' },
  workflowSource: forwardFixSource,
  policy: forwardFixPolicyInput,
  currentHeadSha: monitorCurrentSha,
  controlledRunContext: controlledDisabledMonitorContext,
}), null, 'a generic forward-fix policy must never inherit the controlled monitor exception');
const exactManualIncidentRecoveryRun = {
  id: 800,
  run_attempt: 1,
  workflow_id: monitorWorkflow.id,
  head_branch: 'main',
  head_sha: monitorCurrentSha,
  head_repository: { full_name: 'ScaleSmall/SSAI_Shared' },
  event: 'workflow_dispatch',
  display_title: 'Release health monitor [incident:168h]',
  status: 'completed',
  conclusion: 'success',
};
assert.equal(
  isExactManualIncidentRecoveryRun(exactManualIncidentRecoveryRun, monitorPolicy, 'main'),
  true,
  'only the exact clean manual incident:168h run may be durable recovery evidence',
);
for (const [label, mutation] of [
  ['scheduled success', { event: 'schedule' }],
  ['manual continuous success', { display_title: 'Release health monitor [continuous:6h]' }],
  ['narrow incident success', { display_title: 'Release health monitor [incident:167h]' }],
  ['non-default branch success', { head_branch: 'feature' }],
  ['failed incident', { conclusion: 'failure' }],
]) {
  assert.equal(
    isExactManualIncidentRecoveryRun({ ...exactManualIncidentRecoveryRun, ...mutation }, monitorPolicy, 'main'),
    false,
    label + ' must never become durable monitor recovery evidence',
  );
}
const scheduledDeduplicatedSuccess = { ...exactManualIncidentRecoveryRun, id: 801, event: 'schedule', display_title: 'Release health monitor [continuous:6h]' };
const failedMonitorOrigin = { ...exactManualIncidentRecoveryRun, id: 799, event: 'schedule', display_title: 'Release health monitor [continuous:6h]', conclusion: 'failure' };
assert.deepEqual(
  durableTrustedMonitorRecoveryRuns(
    [failedMonitorOrigin, scheduledDeduplicatedSuccess, exactManualIncidentRecoveryRun],
    monitorPolicy,
    'main',
  ).map((run) => run.id),
  [799, 800],
  'the durable selector must preserve failures and exclude green deduplicated scheduled runs',
);
const exactManualIncidentRecoveryCheck = {
  id: 900,
  workflow_id: monitorWorkflow.id,
  head_branch: 'main',
  head_sha: monitorCurrentSha,
  head_repository: 'ScaleSmall/SSAI_Shared',
  event: 'workflow_dispatch',
  source_run_display_title: 'Release health monitor [incident:168h]',
  name: 'Verify current organization release health',
  status: 'completed',
  conclusion: 'success',
};
assert.equal(
  isExactManualIncidentRecoveryCheck(exactManualIncidentRecoveryCheck, monitorPolicy, 'main'),
  true,
  'the exact manual incident job may be durable recovery evidence',
);
const scheduledDeduplicatedCheck = {
  ...exactManualIncidentRecoveryCheck,
  id: 901,
  event: 'schedule',
  source_run_display_title: 'Release health monitor [continuous:6h]',
};
assert.equal(
  isExactManualIncidentRecoveryCheck(scheduledDeduplicatedCheck, monitorPolicy, 'main'),
  false,
  'a successful scheduled monitor job must never become durable recovery evidence',
);
assert.deepEqual(
  durableTrustedMonitorRecoveryChecks([
    { ...scheduledDeduplicatedCheck, id: 899, conclusion: 'failure' },
    scheduledDeduplicatedCheck,
    exactManualIncidentRecoveryCheck,
  ], monitorPolicy, 'main').map((check) => check.id),
  [899, 900],
  'the durable check selector must exclude successful scheduled monitor jobs',
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
  deliverySource: monitorCurrentDeliverySource,
}), true, 'an exact four-file implementation match may attest a default-main ancestor');
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
    deliverySource: monitorCurrentDeliverySource,
  }), false, label + ' success must not receive source attestation even when its four files match');
  assert.equal(monitorPolicy.attestedMonitorHeadShas.has(candidateSha), false);
}
assert.equal(attestTrustedMonitorImplementation(monitorPolicy, {
  run: { ...monitorEquivalentAncestorRun, id: 803, head_sha: monitorChangedAncestorSha },
  defaultBranch: 'main',
  defaultCommitShas: monitorDefaultCommitShas,
  workflowSource: monitorSource,
  scriptSource: Buffer.from('console.log("changed ancestor");\n', 'utf8'),
  utilsSource: monitorCurrentUtilsSource,
  deliverySource: monitorCurrentDeliverySource,
}), false, 'a changed default-main implementation must not be attested');
for (const [label, mutation] of [
  ['workflow', { workflowSource: monitorSource + '# changed\n' }],
  ['script', { scriptSource: Buffer.from('console.log("changed");\n', 'utf8') }],
  ['utils', { utilsSource: Buffer.from('export const changed = true;\n', 'utf8') }],
  ['delivery', { deliverySource: Buffer.from('export const delivery = false;\n', 'utf8') }],
  ['missing workflow', { workflowSource: null }],
  ['missing script', { scriptSource: null }],
  ['missing utils', { utilsSource: null }],
  ['missing delivery', { deliverySource: null }],
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
    deliverySource: monitorCurrentDeliverySource,
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
  monitorImplementationSource: {
    scriptSource: monitorCurrentScriptSource,
    utilsSource: null,
    deliverySource: monitorCurrentDeliverySource,
  },
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
    deliverySource: null,
  }]]),
}), null, 'a historical implementation digest mismatch must invalidate the entire recovery policy');
assert.equal(verifyForwardFixRecoveryPolicy({
  ...monitorVerificationContext,
  workflow: monitorWorkflow,
  workflowSource: monitorSource,
  policy: monitorPolicyInput,
  auditedOriginSources: new Map([[monitorOldSha, {
    workflowSource: auditedHistoricalWorkflowSource,
    scriptSource: auditedHistoricalScriptSource,
    utilsSource: auditedHistoricalUtilsSource,
    deliverySource: Buffer.from('unexpected historical delivery implementation\n', 'utf8'),
  }]]),
}), null, 'a delivery implementation appearing where historical absence was asserted must invalidate the policy');
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
    deliverySource: null,
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
