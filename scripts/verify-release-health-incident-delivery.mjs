import assert from 'node:assert/strict';
import {
  GitHubApiError,
  incidentDeliveryMarker,
  incidentIssueLabel,
  incidentIssueMarker,
  incidentIssueTitle,
  createGitHubApi,
  selectManagedIncidentIssue,
  syncReleaseHealthIncidentIssue,
} from './sync-release-health-incident-issue.mjs';

const repository = 'ScaleSmall/SSAI_Shared';
const runId = '30264003709';
const deliveryIdentity = 'run-' + runId + '-attempt-1';

function managedIssue(overrides = {}) {
  return {
    number: 42,
    title: incidentIssueTitle,
    body: incidentIssueMarker + '\nprior run',
    state: 'open',
    ...overrides,
  };
}

function apiHarness({
  labelExists = true,
  issues = [],
  failCreateAfterWrite = false,
  failPatchCount = 0,
} = {}) {
  const calls = [];
  const storedIssues = issues.map((issue) => ({ ...issue }));
  const api = async (path, options = {}) => {
    calls.push({ path, options });
    const method = options.method || 'GET';
    if (path.includes('/labels/' + encodeURIComponent(incidentIssueLabel)) && method === 'GET') {
      if (!labelExists) {
        labelExists = true;
        throw new GitHubApiError('missing', 404);
      }
      return { name: incidentIssueLabel };
    }
    if (path.endsWith('/labels') && method === 'POST') return { name: incidentIssueLabel };
    if (path.includes('/issues?')) return storedIssues.map((issue) => ({ ...issue }));
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

{
  const { api, calls } = apiHarness({ labelExists: false });
  const result = await syncReleaseHealthIncidentIssue({
    api,
    repository,
    incidentState: 'incident',
    outcome: 'new-or-worsened-incident',
    runId,
    deliveryIdentity,
  });
  assert.deepEqual(result, { action: 'created', issueNumber: 77 });
  assert.equal(calls.filter((call) => call.options.method === 'POST' && call.path.endsWith('/labels')).length, 1);
  const create = calls.find((call) => call.options.method === 'POST' && call.path.endsWith('/issues'));
  assert.deepEqual(create.options.body.labels, [incidentIssueLabel]);
  assert.match(create.options.body.body, new RegExp(runId));
}

{
  const { api, calls } = apiHarness({ issues: [managedIssue({ state: 'closed' })] });
  const result = await syncReleaseHealthIncidentIssue({
    api,
    repository,
    incidentState: 'incident',
    outcome: 'new-or-worsened-incident',
    runId,
    deliveryIdentity,
  });
  assert.deepEqual(result, { action: 'reopened', issueNumber: 42 });
  const update = calls.find((call) => call.options.method === 'PATCH');
  assert.equal(update.options.body.state, 'open');
  assert.equal(update.options.body.state_reason, 'reopened');
}

{
  const { api, calls } = apiHarness({ issues: [managedIssue()] });
  const result = await syncReleaseHealthIncidentIssue({
    api,
    repository,
    incidentState: 'healthy',
    outcome: 'healthy',
    runId,
    deliveryIdentity,
  });
  assert.deepEqual(result, { action: 'closed', issueNumber: 42 });
  const update = calls.find((call) => call.options.method === 'PATCH');
  assert.equal(update.options.body.state, 'closed');
  assert.equal(update.options.body.state_reason, 'completed');
}

{
  const { api } = apiHarness({ issues: [] });
  assert.deepEqual(
    await syncReleaseHealthIncidentIssue({
      api, repository, incidentState: 'healthy', outcome: 'healthy', runId, deliveryIdentity,
    }),
    { action: 'already-closed', issueNumber: null },
  );
}

{
  const harness = apiHarness({
    issues: [managedIssue({ state: 'closed', state_reason: 'completed' })],
  });
  assert.deepEqual(
    await syncReleaseHealthIncidentIssue({
      api: harness.api,
      repository,
      incidentState: 'healthy',
      outcome: 'healthy',
      runId,
      deliveryIdentity,
    }),
    { action: 'updated', issueNumber: 42 },
    'a closed issue with a stale incident body must converge to the authenticated healthy delivery',
  );
  assert.deepEqual(
    await syncReleaseHealthIncidentIssue({
      api: harness.api,
      repository,
      incidentState: 'healthy',
      outcome: 'healthy',
      runId,
      deliveryIdentity,
    }),
    { action: 'already-closed', issueNumber: 42 },
    'an identical healthy reconciliation must be idempotent after convergence',
  );
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'PATCH').length,
    1,
    'closed healthy reconciliation must PATCH exactly once',
  );
}

{
  const { api } = apiHarness({ issues: [], failCreateAfterWrite: true });
  assert.deepEqual(
    await syncReleaseHealthIncidentIssue({
      api,
      repository,
      incidentState: 'incident',
      outcome: 'new-or-worsened-incident',
      runId,
      deliveryIdentity,
    }),
    { action: 'created', issueNumber: 77 },
    'an ambiguous create must reconcile to the exact run marker without creating a duplicate',
  );
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
  syncReleaseHealthIncidentIssue({
    api: apiHarness().api,
    repository: 'attacker/fork',
    incidentState: 'incident',
    outcome: 'new-or-worsened-incident',
    runId,
    deliveryIdentity,
  }),
  /restricted to ScaleSmall\/SSAI_Shared/,
);
await assert.rejects(
  syncReleaseHealthIncidentIssue({
    api: apiHarness().api,
    repository,
    incidentState: 'healthy',
    outcome: 'known-incident-suppressed',
    runId,
    deliveryIdentity,
  }),
  /state and outcome are inconsistent/,
);
await assert.rejects(
  syncReleaseHealthIncidentIssue({
    api: apiHarness({ issues: [managedIssue({ number: 'not-a-number' })] }).api,
    repository,
    incidentState: 'healthy',
    outcome: 'healthy',
    runId,
    deliveryIdentity,
  }),
  /issue number is invalid/,
);

{
  const seeded = apiHarness({ issues: [] });
  await syncReleaseHealthIncidentIssue({
    api: seeded.api,
    repository,
    incidentState: 'incident',
    outcome: 'new-or-worsened-incident',
    runId,
    deliveryIdentity,
  });
  const { api, calls } = apiHarness({ issues: seeded.storedIssues });
  const result = await syncReleaseHealthIncidentIssue({
    api,
    repository,
    incidentState: 'incident',
    outcome: 'known-incident-suppressed',
    runId,
    deliveryIdentity,
  });
  assert.deepEqual(result, { action: 'already-open', issueNumber: 77 });
  assert.equal(calls.filter((call) => call.options.method === 'PATCH').length, 0);
}

for (const suppressedOutcome of ['known-incident-suppressed', 'incident-improved-suppressed']) {
  const nextRunId = '30264003710';
  const nextDeliveryIdentity = suppressedOutcome === 'known-incident-suppressed'
    ? deliveryIdentity
    : 'run-' + nextRunId + '-attempt-1';
  const harness = apiHarness({
    issues: [managedIssue()],
    failPatchCount: 1,
  });

  await assert.rejects(
    syncReleaseHealthIncidentIssue({
      api: harness.api,
      repository,
      incidentState: 'incident',
      outcome: 'new-or-worsened-incident',
      runId,
      deliveryIdentity,
    }),
    /exhausted PATCH failure/,
    'the first run must surface an exhausted managed-issue PATCH failure',
  );
  assert.equal(harness.storedIssues[0].body, incidentIssueMarker + '\nprior run');

  assert.deepEqual(
    await syncReleaseHealthIncidentIssue({
      api: harness.api,
      repository,
      incidentState: 'incident',
      outcome: suppressedOutcome,
      runId: nextRunId,
      deliveryIdentity: nextDeliveryIdentity,
    }),
    { action: 'updated', issueNumber: 42 },
    'the next natural suppressed scan must repair the stale managed issue',
  );
  assert.equal(harness.storedIssues.length, 1, 'reconciliation must not create a duplicate issue');
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'POST' && call.path.endsWith('/issues')).length,
    0,
    'reconciliation of an existing issue must not attempt issue creation',
  );
  assert.equal(
    harness.calls.filter((call) => call.options.method === 'PATCH').length,
    2,
    'the two-run sequence must attempt one failed PATCH and one repairing PATCH',
  );
  assert.equal(
    harness.storedIssues[0].body.includes(incidentDeliveryMarker(nextDeliveryIdentity)),
    true,
    'the repaired body must carry the expected stable delivery identity',
  );
  const authoritativeRunId = suppressedOutcome === 'known-incident-suppressed' ? runId : nextRunId;
  assert.match(harness.storedIssues[0].body, new RegExp('/actions/runs/' + authoritativeRunId));
  if (suppressedOutcome === 'known-incident-suppressed') {
    assert.doesNotMatch(
      harness.storedIssues[0].body,
      new RegExp('/actions/runs/' + nextRunId),
      'an unchanged scan must preserve the original state-transition run identity',
    );
  }
}

{
  const { api } = apiHarness({ issues: [] });
  assert.deepEqual(
    await syncReleaseHealthIncidentIssue({
      api,
      repository,
      incidentState: 'incident',
      outcome: 'incident-improved-suppressed',
      runId,
      deliveryIdentity,
    }),
    { action: 'created', issueNumber: 77 },
    'an unchanged or improved incident must reconcile a missing issue on the next schedule',
  );
}

assert.throws(
  () => createGitHubApi({ token: 'x'.repeat(20), apiUrl: 'https://example.invalid' }),
  /GITHUB_API_URL is not approved/,
);
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
  assert.equal(calls, 1, 'non-idempotent issue creation must never be retried blindly');
  await assert.rejects(api('/repos/attacker/fork/issues'), /outside the repository boundary/);
  await assert.rejects(api('/repos/ScaleSmall/SSAI_Shared/issues', { method: 'DELETE' }), /method is not approved/);
}

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
  assert.equal(calls, 2, 'a non-JSON transient response must be retried before JSON parsing');
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
  assert.equal(calls, 2, 'HTTP 429 must be retried with its bounded Retry-After delay');
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
  assert.deepEqual(await api('/repos/ScaleSmall/SSAI_Shared/issues/42', { method: 'PATCH', body: {} }), { ok: true });
  assert.equal(calls, 2, 'a header-confirmed GitHub secondary rate limit must be retried');
  assert.deepEqual(delays, [10_000]);
}

console.log('Release-health incident delivery tests passed.');
