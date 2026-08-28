import assert from 'node:assert/strict';
import {
  GitHubApiError,
  OperatorReconciliationRequiredError,
  activeIncidentWorkflowId,
  createGitHubApi,
  incidentDeliveryMarker,
  incidentIssueLabel,
  incidentIssueMarker,
  incidentIssueTitle,
  rejectedCanaryWorkflowId,
  fallbackIncidentWorkflowId,
  selectManagedIncidentIssue,
  syncReleaseHealthIncidentIssue,
} from './sync-release-health-incident-issue.mjs';
import { releaseHealthMonitorWorkflowIdentities } from './release-health-monitor-utils.mjs';

assert.equal(
  activeIncidentWorkflowId,
  releaseHealthMonitorWorkflowIdentities.active.workflowId,
  'incident delivery must use the canonical active workflow identity',
);
assert.equal(rejectedCanaryWorkflowId, 344135917, 'the scheduler canary identity must remain explicitly rejected');
assert.equal(fallbackIncidentWorkflowId, 344170407, 'the independent fallback identity must be explicitly authorized');

const repository = 'ScaleSmall/SSAI_Shared';
const currentRunId = '33120000002';
const currentRunAttempt = '2';
const currentHeadSha = 'c'.repeat(40);
const currentCreatedAt = '2026-08-27T22:30:00Z';
const priorRunId = '33082876414';
const priorRunAttempt = '1';
const priorHeadSha = 'a'.repeat(40);
const priorCreatedAt = '2026-08-27T18:00:00Z';

function deliveryIdentity(runId = currentRunId, runAttempt = currentRunAttempt) {
  return 'run-' + runId + '-attempt-' + runAttempt;
}

function legacyDeliveryMarker(runId = priorRunId, runAttempt = priorRunAttempt) {
  return '<!-- ssai-release-health-monitor:delivery:v1 '
    + deliveryIdentity(runId, runAttempt) + ' -->';
}

function issueBody(marker, workflowPath = releaseHealthMonitorWorkflowIdentities.active.path) {
  return [
    incidentIssueMarker,
    marker,
    '',
    'The protected release-health monitor detected an incident that remains active.',
    '',
    '_Managed automatically by `' + workflowPath + '`._',
  ].join('\n');
}

function managedIssue({
  marker = legacyDeliveryMarker(),
  number = 42,
  state = 'open',
  stateReason = undefined,
  body = issueBody(marker),
  labels = [{ name: incidentIssueLabel }],
  updatedAt = '2026-08-27T18:01:00Z',
} = {}) {
  return {
    number,
    title: incidentIssueTitle,
    body,
    state,
    labels,
    updated_at: updatedAt,
    ...(stateReason === undefined ? {} : { state_reason: stateReason }),
  };
}

function runFixture({
  id = currentRunId,
  runAttempt = currentRunAttempt,
  workflowId = activeIncidentWorkflowId,
  event = 'schedule',
  fullName = repository,
  repositoryId = 1183552904,
  path = workflowId === fallbackIncidentWorkflowId
    ? '.github/workflows/release-health-monitor-fallback.yml@main'
    : '.github/workflows/release-health-monitor.yml@refs/heads/main',
  headBranch = 'main',
  headSha = currentHeadSha,
  createdAt = currentCreatedAt,
} = {}) {
  return {
    id,
    run_attempt: Number(runAttempt),
    workflow_id: workflowId,
    path,
    event,
    repository: { id: repositoryId, full_name: fullName },
    head_branch: headBranch,
    head_sha: headSha,
    created_at: createdAt,
  };
}

function priorRunFixture(overrides = {}) {
  return runFixture({
    id: priorRunId,
    runAttempt: priorRunAttempt,
    workflowId: activeIncidentWorkflowId,
    headSha: priorHeadSha,
    createdAt: priorCreatedAt,
    ...overrides,
  });
}

function apiHarness({
  labelExists = true,
  issues = [],
  runs = [runFixture(), priorRunFixture()],
  missingRuns = [],
  failCreateAfterWrite = false,
  failPatchCount = 0,
  exactIssueReads = [],
} = {}) {
  const calls = [];
  const storedIssues = issues.map((issue) => ({
    ...issue,
    labels: Array.isArray(issue.labels) ? issue.labels.map((label) => ({ ...label })) : issue.labels,
  }));
  let exactIssueReadIndex = 0;
  const runByAttempt = new Map(runs.map((run) => {
    const { _lookupAttempt, ...payload } = run;
    return [
      String(run.id) + ':' + String(_lookupAttempt ?? run.run_attempt),
      { ...payload, repository: run.repository ? { ...run.repository } : run.repository },
    ];
  }));
  const missing = new Set(missingRuns);
  const api = async (path, options = {}) => {
    calls.push({ path, options });
    const method = options.method || 'GET';
    const runMatch = /\/actions\/runs\/([1-9][0-9]*)\/attempts\/([1-9][0-9]*)$/.exec(path);
    if (runMatch && method === 'GET') {
      const key = runMatch[1] + ':' + runMatch[2];
      if (missing.has(key) || !runByAttempt.has(key)) throw new GitHubApiError('missing', 404);
      const run = runByAttempt.get(key);
      return { ...run, repository: run.repository ? { ...run.repository } : run.repository };
    }
    if (path.includes('/labels/' + encodeURIComponent(incidentIssueLabel)) && method === 'GET') {
      if (!labelExists) {
        labelExists = true;
        throw new GitHubApiError('missing', 404);
      }
      return { name: incidentIssueLabel };
    }
    if (path.endsWith('/labels') && method === 'POST') return { name: incidentIssueLabel };
    if (path.includes('/issues?') && method === 'GET') {
      return storedIssues.map((issue) => ({ ...issue }));
    }
    if (/\/issues\/\d+$/.test(path) && method === 'GET') {
      const number = Number(path.slice(path.lastIndexOf('/') + 1));
      const index = storedIssues.findIndex((issue) => issue.number === number);
      if (index < 0) throw new GitHubApiError('missing', 404);
      if (exactIssueReadIndex < exactIssueReads.length) {
        const interleaving = exactIssueReads[exactIssueReadIndex];
        exactIssueReadIndex += 1;
        const nextIssue = typeof interleaving === 'function'
          ? interleaving({ ...storedIssues[index] })
          : interleaving;
        storedIssues[index] = {
          ...nextIssue,
          labels: Array.isArray(nextIssue?.labels)
            ? nextIssue.labels.map((label) => ({ ...label }))
            : nextIssue?.labels,
        };
      }
      return {
        ...storedIssues[index],
        labels: Array.isArray(storedIssues[index].labels)
          ? storedIssues[index].labels.map((label) => ({ ...label }))
          : storedIssues[index].labels,
      };
    }
    if (path.endsWith('/issues') && method === 'POST') {
      const createdIssue = managedIssue({ number: 77, body: options.body.body });
      storedIssues.push(createdIssue);
      if (failCreateAfterWrite) throw new Error('ambiguous transport failure');
      return { ...createdIssue };
    }
    if (/\/issues\/\d+$/.test(path) && method === 'PATCH') {
      if (failPatchCount > 0) {
        failPatchCount -= 1;
        throw new Error('exhausted PATCH failure');
      }
      const number = Number(path.slice(path.lastIndexOf('/') + 1));
      const index = storedIssues.findIndex((issue) => issue.number === number);
      if (index < 0) throw new Error('PATCH target is missing.');
      storedIssues[index] = { ...storedIssues[index], ...options.body };
      return { ...storedIssues[index] };
    }
    throw new Error('Unexpected API call: ' + method + ' ' + path);
  };
  return { api, calls, storedIssues };
}

function sync(harness, overrides = {}) {
  return syncReleaseHealthIncidentIssue({
    api: harness.api,
    repository,
    incidentState: 'incident',
    outcome: 'new-or-worsened-incident',
    runId: currentRunId,
    runAttempt: currentRunAttempt,
    headSha: currentHeadSha,
    deliveryIdentity: deliveryIdentity(),
    ...overrides,
  });
}

function mutationCalls(calls) {
  return calls.filter((call) => ['POST', 'PATCH'].includes(call.options.method));
}

function assertFinalIssueReadImmediatelyPrecedesPatch(calls, number = 42) {
  const patchIndex = calls.findIndex((call) => call.options.method === 'PATCH');
  assert.ok(patchIndex > 0, 'a PATCH call must exist');
  assert.deepEqual(
    {
      path: calls[patchIndex - 1].path,
      method: calls[patchIndex - 1].options.method || 'GET',
    },
    {
      path: '/repos/' + repository + '/issues/' + number,
      method: 'GET',
    },
    'the final exact issue GET must be directly adjacent to PATCH with no intervening request',
  );
}

// A fresh incident is created only after the active scheduled run is attested.
{
  const harness = apiHarness({ labelExists: false, issues: [] });
  const result = await sync(harness);
  assert.deepEqual(result, { action: 'created', issueNumber: 77 });
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'POST' && call.path.endsWith('/labels')).length,
    1,
  );
  const create = harness.calls.find(
    (call) => call.options.method === 'POST' && call.path.endsWith('/issues'),
  );
  assert.deepEqual(create.options.body.labels, [incidentIssueLabel]);
  assert.match(create.options.body.body, new RegExp(currentRunId));
  assert.ok(create.options.body.body.includes(incidentDeliveryMarker(deliveryIdentity())));
  assert.ok(create.options.body.body.includes(releaseHealthMonitorWorkflowIdentities.active.path));
}

// The existing v1 issue is migrated in place after its old registered run is attested.
{
  const fallbackRun = runFixture({ workflowId: fallbackIncidentWorkflowId, event: 'workflow_dispatch', runAttempt: '1' });
  const harness = apiHarness({ issues: [], runs: [fallbackRun] });
  assert.deepEqual(await sync(harness, { runAttempt: '1', deliveryIdentity: deliveryIdentity(currentRunId, '1') }), { action: 'created', issueNumber: 77 });
  assert.match(harness.storedIssues[0].body, /Producer: independent fallback/);
  assert.match(harness.storedIssues[0].body, /workflow-344170407/);
}

// The existing v1 issue is migrated in place after its old registered run is attested.
{
  const harness = apiHarness({ issues: [managedIssue()] });
  const result = await sync(harness, { outcome: 'known-incident-suppressed' });
  assert.deepEqual(result, { action: 'updated', issueNumber: 42 });
  assertFinalIssueReadImmediatelyPrecedesPatch(harness.calls);
  assert.equal(harness.storedIssues.length, 1);
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'PATCH').length,
    1,
    'the legacy managed issue must be patched in place exactly once',
  );
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'POST' && call.path.endsWith('/issues')).length,
    0,
    'v1 migration must never create a duplicate issue',
  );
  assert.ok(harness.storedIssues[0].body.includes(incidentDeliveryMarker(deliveryIdentity())));
  assert.ok(harness.storedIssues[0].body.includes(releaseHealthMonitorWorkflowIdentities.active.path));
}

// A v2 marker may safely reference the current authoritative native workflow.
{
  const oldMarker = incidentDeliveryMarker(
    deliveryIdentity(priorRunId, priorRunAttempt),
    activeIncidentWorkflowId,
  );
  const harness = apiHarness({ issues: [managedIssue({ marker: oldMarker })] });
  assert.deepEqual(await sync(harness), { action: 'updated', issueNumber: 42 });
  assert.equal(harness.calls.filter((call) => call.options.method === 'PATCH').length, 1);
  assertFinalIssueReadImmediatelyPrecedesPatch(harness.calls);
}

// A newer native authority is allowed to update the same managed issue, never create another one.
{
  const newerPriorId = '33120000001';
  const priorMarker = incidentDeliveryMarker(deliveryIdentity(newerPriorId, '1'));
  const harness = apiHarness({
    issues: [managedIssue({ marker: priorMarker })],
    runs: [
      runFixture(),
      runFixture({
        id: newerPriorId,
        runAttempt: '1',
        headSha: 'b'.repeat(40),
        createdAt: '2026-08-27T22:29:00Z',
      }),
    ],
  });
  assert.deepEqual(await sync(harness), { action: 'updated', issueNumber: 42 });
  assert.equal(harness.calls.filter((call) => call.options.method === 'PATCH').length, 1);
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'POST' && call.path.endsWith('/issues')).length,
    0,
  );
}

// Older candidates are explicitly suppressed without any mutation.
{
  const laterRunId = '33120000003';
  const laterMarker = incidentDeliveryMarker(deliveryIdentity(laterRunId, '1'));
  const harness = apiHarness({
    issues: [managedIssue({ marker: laterMarker })],
    runs: [
      runFixture(),
      runFixture({
        id: laterRunId,
        runAttempt: '1',
        headSha: 'd'.repeat(40),
        createdAt: '2026-08-27T22:31:00Z',
      }),
    ],
  });
  assert.deepEqual(await sync(harness), { action: 'stale-suppressed', issueNumber: 42 });
  assert.deepEqual(mutationCalls(harness.calls), []);
}

// Ordering falls back to numeric run ID when GitHub timestamps are equal.
{
  const lowerRunId = '33120000001';
  const marker = incidentDeliveryMarker(deliveryIdentity(lowerRunId, '1'));
  const harness = apiHarness({
    issues: [managedIssue({ marker })],
    runs: [
      runFixture(),
      runFixture({
        id: lowerRunId,
        runAttempt: '1',
        headSha: 'b'.repeat(40),
        createdAt: currentCreatedAt,
      }),
    ],
  });
  assert.deepEqual(await sync(harness), { action: 'updated', issueNumber: 42 });
}

// Ordering falls back to the numeric attempt for reruns of the same run.
{
  const attemptOneMarker = incidentDeliveryMarker(deliveryIdentity(currentRunId, '1'));
  const harness = apiHarness({
    issues: [managedIssue({ marker: attemptOneMarker })],
    runs: [
      runFixture(),
      runFixture({ runAttempt: '1' }),
    ],
  });
  assert.deepEqual(await sync(harness), { action: 'updated', issueNumber: 42 });
}

// An exact v2 duplicate is a no-op.
{
  const seeded = apiHarness({ issues: [] });
  await sync(seeded);
  const harness = apiHarness({ issues: seeded.storedIssues, runs: [runFixture()] });
  assert.deepEqual(await sync(harness), { action: 'already-open', issueNumber: 77 });
  assert.deepEqual(mutationCalls(harness.calls), []);
}

// A closed issue reopens on a newer incident authority.
{
  const harness = apiHarness({ issues: [managedIssue({ state: 'closed' })] });
  assert.deepEqual(await sync(harness), { action: 'reopened', issueNumber: 42 });
  const update = harness.calls.find((call) => call.options.method === 'PATCH');
  assert.equal(update.options.body.state, 'open');
  assert.equal(update.options.body.state_reason, 'reopened');
}

// A newer healthy authority closes the one managed issue.
{
  const harness = apiHarness({ issues: [managedIssue()] });
  assert.deepEqual(
    await sync(harness, { incidentState: 'healthy', outcome: 'healthy' }),
    { action: 'closed', issueNumber: 42 },
  );
  const update = harness.calls.find((call) => call.options.method === 'PATCH');
  assert.equal(update.options.body.state, 'closed');
  assert.equal(update.options.body.state_reason, 'completed');
}

// Healthy state with no managed issue is read-only.
{
  const harness = apiHarness({ issues: [] });
  assert.deepEqual(
    await sync(harness, { incidentState: 'healthy', outcome: 'healthy' }),
    { action: 'already-closed', issueNumber: null },
  );
  assert.deepEqual(mutationCalls(harness.calls), []);
}

// An ambiguous create reconciles the exact v2 body and does not POST twice.
{
  const harness = apiHarness({ issues: [], failCreateAfterWrite: true });
  assert.deepEqual(await sync(harness), { action: 'created', issueNumber: 77 });
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'POST' && call.path.endsWith('/issues')).length,
    1,
  );
  assert.equal(harness.storedIssues.length, 1);
}

// Input provenance binds the delivery identity to the executing run and attempt.
await assert.rejects(
  sync(apiHarness(), {
    deliveryIdentity: deliveryIdentity('33120000001', currentRunAttempt),
  }),
  /not bound to GITHUB_RUN_ID/,
);
await assert.rejects(
  sync(apiHarness(), {
    deliveryIdentity: deliveryIdentity(currentRunId, '1'),
  }),
  /not bound to GITHUB_RUN_ATTEMPT/,
);

// Every active candidate metadata boundary is checked before any issue mutation.
for (const [label, runMutation, expected] of [
  ['canary workflow', { workflow_id: rejectedCanaryWorkflowId }, /identity is not registered/],
  ['wrong event', { event: 'workflow_dispatch' }, /producer is not authorized/],
  ['wrong repository', { repository: { full_name: 'attacker/fork' } }, /outside the managed boundary/],
  ['wrong branch', { head_branch: 'release' }, /branch is not main/],
  ['wrong SHA', { head_sha: 'f'.repeat(40) }, /does not match GITHUB_SHA/],
  ['wrong attempt', { run_attempt: 1, _lookupAttempt: 2 }, /identity does not match its delivery marker/],
]) {
  const exactRun = { ...runFixture(), ...runMutation };
  const harness = apiHarness({ issues: [], runs: [exactRun] });
  await assert.rejects(sync(harness), expected, label);
  assert.deepEqual(mutationCalls(harness.calls), [], label + ' must fail before mutation');
}

// Canary identities remain rejected even when a marker is syntactically valid.
{
  for (const rejectedWorkflowId of [rejectedCanaryWorkflowId]) {
    assert.throws(
      () => incidentDeliveryMarker(deliveryIdentity(priorRunId, priorRunAttempt), rejectedWorkflowId),
      /workflow ID is not registered/,
    );
    const rejectedMarker = '<!-- ssai-release-health-monitor:delivery:v2 workflow-'
      + rejectedWorkflowId + ' ' + deliveryIdentity(priorRunId, priorRunAttempt) + ' -->';
    const harness = apiHarness({ issues: [managedIssue({ marker: rejectedMarker })] });
    await assert.rejects(sync(harness), OperatorReconciliationRequiredError);
    assert.deepEqual(mutationCalls(harness.calls), []);
  }
}

for (const [label, priorMutation] of [
  ['wrong prior event', { event: 'workflow_dispatch' }],
  ['wrong prior repository', { repository: { full_name: 'attacker/fork' } }],
  ['wrong prior branch', { head_branch: 'release' }],
  ['wrong prior attempt', { run_attempt: 2, _lookupAttempt: 1 }],
]) {
  const harness = apiHarness({
    issues: [managedIssue()],
    runs: [runFixture(), { ...priorRunFixture(), ...priorMutation }],
  });
  await assert.rejects(sync(harness), OperatorReconciliationRequiredError, label);
  assert.deepEqual(mutationCalls(harness.calls), [], label + ' must fail before mutation');
}

// Missing, deleted, malformed, or ambiguous prior authority always requires an operator.
{
  const harness = apiHarness({
    issues: [managedIssue()],
    runs: [runFixture()],
    missingRuns: [priorRunId + ':' + priorRunAttempt],
  });
  await assert.rejects(
    sync(harness),
    /Operator reconciliation required: the prior authoritative workflow run is missing or deleted/,
  );
  assert.deepEqual(mutationCalls(harness.calls), []);
}
for (const body of [
  incidentIssueMarker + '\nprior run without authority',
  incidentIssueMarker + '\n<!-- ssai-release-health-monitor:delivery:v2 malformed -->',
  issueBody(legacyDeliveryMarker()) + '\n' + legacyDeliveryMarker('33082876415', '1'),
]) {
  const harness = apiHarness({ issues: [managedIssue({ body })] });
  await assert.rejects(sync(harness), OperatorReconciliationRequiredError);
  assert.deepEqual(mutationCalls(harness.calls), []);
}

assert.throws(
  () => selectManagedIncidentIssue([managedIssue(), managedIssue({ number: 43 })]),
  /Multiple managed incident issues/,
);
assert.throws(
  () => selectManagedIncidentIssue([{ ...managedIssue(), body: 'unmanaged' }]),
  /reserved incident label is attached to an unmanaged issue/,
);
await assert.rejects(
  sync(apiHarness(), { repository: 'attacker/fork' }),
  /restricted to ScaleSmall\/SSAI_Shared/,
);
await assert.rejects(
  sync(apiHarness(), { incidentState: 'healthy', outcome: 'known-incident-suppressed' }),
  /state and outcome are inconsistent/,
);
await assert.rejects(
  sync(apiHarness({ issues: [managedIssue({ number: 'not-a-number' })] })),
  /issue number is invalid/,
);

// A later authoritative issue delivery appearing after the list read fences an older candidate.
{
  const laterRunId = '33120000003';
  const laterRun = runFixture({
    id: laterRunId,
    runAttempt: '1',
    headSha: 'd'.repeat(40),
    createdAt: '2026-08-27T22:31:00Z',
  });
  const laterMarker = incidentDeliveryMarker(deliveryIdentity(laterRunId, '1'));
  const harness = apiHarness({
    issues: [managedIssue()],
    runs: [runFixture(), priorRunFixture(), laterRun],
    exactIssueReads: [managedIssue({
      marker: laterMarker,
      updatedAt: '2026-08-27T22:31:30Z',
    })],
  });
  assert.deepEqual(await sync(harness), { action: 'stale-suppressed', issueNumber: 42 });
  assert.deepEqual(mutationCalls(harness.calls), []);
}

// A same-marker operator edit between list and PATCH fails closed instead of being overwritten.
{
  const currentMarker = incidentDeliveryMarker(deliveryIdentity());
  const initial = managedIssue({
    marker: currentMarker,
    updatedAt: '2026-08-27T22:30:10Z',
  });
  const harness = apiHarness({
    issues: [initial],
    runs: [runFixture()],
    exactIssueReads: [{
      ...initial,
      body: initial.body + '\nOperator note preserved by the mutation fence.',
      updated_at: '2026-08-27T22:30:20Z',
    }],
  });
  await assert.rejects(
    sync(harness),
    /changed without an authoritative delivery-marker advance/,
  );
  assert.deepEqual(mutationCalls(harness.calls), []);
}

// A candidate newer than an interleaved authoritative delivery may update exactly once.
{
  const middleRunId = '33120000001';
  const middleRun = runFixture({
    id: middleRunId,
    runAttempt: '1',
    headSha: 'b'.repeat(40),
    createdAt: '2026-08-27T20:00:00Z',
  });
  const middleMarker = incidentDeliveryMarker(deliveryIdentity(middleRunId, '1'));
  const harness = apiHarness({
    issues: [managedIssue()],
    runs: [runFixture(), priorRunFixture(), middleRun],
    exactIssueReads: [managedIssue({
      marker: middleMarker,
      updatedAt: '2026-08-27T20:00:30Z',
    })],
  });
  assert.deepEqual(await sync(harness), { action: 'updated', issueNumber: 42 });
  assert.equal(harness.calls.filter((call) => call.options.method === 'PATCH').length, 1);
  assertFinalIssueReadImmediatelyPrecedesPatch(harness.calls);
}

// A second marker advance during the single bounded prefetch fails closed without looping.
{
  const middleRunId = '33120000001';
  const laterRunId = '33120000003';
  const harness = apiHarness({
    issues: [managedIssue()],
    runs: [
      runFixture(),
      priorRunFixture(),
      runFixture({
        id: middleRunId,
        runAttempt: '1',
        headSha: 'b'.repeat(40),
        createdAt: '2026-08-27T20:00:00Z',
      }),
    ],
    exactIssueReads: [
      managedIssue({
        marker: incidentDeliveryMarker(deliveryIdentity(middleRunId, '1')),
        updatedAt: '2026-08-27T20:00:30Z',
      }),
      managedIssue({
        marker: incidentDeliveryMarker(deliveryIdentity(laterRunId, '1')),
        updatedAt: '2026-08-27T22:31:30Z',
      }),
    ],
  });
  await assert.rejects(sync(harness), /delivery marker advanced again during bounded revalidation/);
  assert.deepEqual(mutationCalls(harness.calls), []);
  assert.equal(
    harness.calls.filter((call) => /\/issues\/42$/.test(call.path) && !call.options.method).length,
    2,
  );
}

// A failed PATCH remains visible; the next newer natural run repairs the same issue.
{
  const firstRunId = '33120000001';
  const firstMarker = incidentDeliveryMarker(deliveryIdentity(firstRunId, '1'));
  const firstRun = runFixture({
    id: firstRunId,
    runAttempt: '1',
    headSha: 'b'.repeat(40),
    createdAt: '2026-08-27T22:29:00Z',
  });
  const harness = apiHarness({
    issues: [managedIssue({ marker: firstMarker })],
    runs: [runFixture(), firstRun],
    failPatchCount: 1,
  });
  await assert.rejects(
    sync(harness),
    /exhausted PATCH failure/,
  );
  assert.deepEqual(
    await sync(harness, { outcome: 'incident-improved-suppressed' }),
    { action: 'updated', issueNumber: 42 },
  );
  assert.equal(harness.storedIssues.length, 1);
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'POST' && call.path.endsWith('/issues')).length,
    0,
  );
  assert.equal(harness.calls.filter((call) => call.options.method === 'PATCH').length, 2);
}

assert.throws(
  () => createGitHubApi({ token: 'x'.repeat(20), apiUrl: 'https://example.invalid' }),
  /GITHUB_API_URL is not approved/,
);

// Non-idempotent creation is never retried blindly, and API scope/methods remain bounded.
{
  let calls = 0;
  const api = createGitHubApi({
    token: 'x'.repeat(20),
    fetchImpl: async () => {
      calls += 1;
      return new Response(JSON.stringify({ message: 'unavailable' }), { status: 503 });
    },
  });
  await assert.rejects(
    api('/repos/ScaleSmall/SSAI_Shared/issues', { method: 'POST', body: {} }),
    /HTTP 503/,
  );
  assert.equal(calls, 1);
  await assert.rejects(api('/repos/attacker/fork/issues'), /outside the repository boundary/);
  await assert.rejects(
    api('/repos/ScaleSmall/SSAI_Shared/issues', { method: 'DELETE' }),
    /method is not approved/,
  );
}

// Idempotent GET and PATCH operations retain bounded, jitter-capable retry behavior.
{
  const delays = [];
  let calls = 0;
  const api = createGitHubApi({
    token: 'x'.repeat(20),
    randomImpl: () => 0,
    nowImpl: () => 1_000_000,
    sleepImpl: async (delayMs) => { delays.push(delayMs); },
    fetchImpl: async () => {
      calls += 1;
      if (calls === 1) {
        return new Response('gateway text', {
          status: 503,
          headers: { 'Retry-After': '2', 'Content-Type': 'text/plain' },
        });
      }
      return new Response(JSON.stringify([]), { status: 200 });
    },
  });
  assert.deepEqual(await api('/repos/ScaleSmall/SSAI_Shared/issues'), []);
  assert.equal(calls, 2);
  assert.deepEqual(delays, [2_000]);
}

{
  const delays = [];
  let calls = 0;
  const api = createGitHubApi({
    token: 'x'.repeat(20),
    randomImpl: () => 0,
    sleepImpl: async (delayMs) => { delays.push(delayMs); },
    fetchImpl: async () => {
      calls += 1;
      if (calls === 1) {
        return new Response('too many requests', {
          status: 429,
          headers: { 'Retry-After': '3' },
        });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    },
  });
  assert.deepEqual(await api('/repos/ScaleSmall/SSAI_Shared/issues'), { ok: true });
  assert.equal(calls, 2);
  assert.deepEqual(delays, [3_000]);
}

{
  const delays = [];
  let calls = 0;
  const resetSeconds = 1_010;
  const api = createGitHubApi({
    token: 'x'.repeat(20),
    randomImpl: () => 0,
    nowImpl: () => 1_000_000,
    sleepImpl: async (delayMs) => { delays.push(delayMs); },
    fetchImpl: async () => {
      calls += 1;
      if (calls === 1) {
        return new Response('rate limited', {
          status: 403,
          headers: {
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': String(resetSeconds),
          },
        });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    },
  });
  assert.deepEqual(
    await api('/repos/ScaleSmall/SSAI_Shared/issues/42', { method: 'PATCH', body: {} }),
    { ok: true },
  );
  assert.equal(calls, 2);
  assert.deepEqual(delays, [10_000]);
}

console.log('Release-health incident delivery tests passed.');
