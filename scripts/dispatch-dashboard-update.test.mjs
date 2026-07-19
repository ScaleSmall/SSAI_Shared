import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  DASHBOARD_MAIN_SHA,
  DASHBOARD_REPOSITORY,
  DASHBOARD_WORKFLOW_PATH,
  GitHubApi,
  createDispatchBody,
  validateDashboardMainRef,
  validateDashboardRepository,
  validateDashboardWorkflow,
  validateDashboardWorkflowFile,
  validateDrainedRunStatus,
  validateFreshRunWitness,
  validateProducerContext,
} from './dispatch-dashboard-update.mjs';

const producerContext = (overrides = {}) => ({
  repository: 'ScaleSmall/SSAI_Shared',
  ref: 'refs/heads/main',
  sha: '6'.repeat(40),
  eventName: 'workflow_dispatch',
  runAttempt: '1',
  apiUrl: 'https://api.github.com',
  ...overrides,
});

const workflowRun = (overrides = {}) => ({
  id: 9001,
  workflow_id: 7001,
  event: 'repository_dispatch',
  path: DASHBOARD_WORKFLOW_PATH,
  head_branch: 'main',
  head_sha: DASHBOARD_MAIN_SHA,
  run_attempt: 1,
  status: 'queued',
  conclusion: null,
  created_at: '2026-07-19T20:00:01.000Z',
  html_url: `https://github.com/${DASHBOARD_REPOSITORY}/actions/runs/9001`,
  repository: { full_name: DASHBOARD_REPOSITORY },
  head_repository: { full_name: DASHBOARD_REPOSITORY },
  ...overrides,
});

const runsPayload = (workflowRuns) => ({
  total_count: workflowRuns.length,
  workflow_runs: workflowRuns,
});

const witnessOptions = (overrides = {}) => ({
  baselineIds: new Set([100, 101]),
  dispatchStartedAt: '2026-07-19T20:00:00.000Z',
  workflowId: 7001,
  ...overrides,
});

test('builds the exact five-key numeric-v2 Dashboard dispatch contract', () => {
  const context = producerContext();
  const body = createDispatchBody(context);
  assert.deepEqual(body, {
    event_type: 'shared-updated',
    client_payload: {
      schema_version: 2,
      repository: 'ScaleSmall/SSAI_Shared',
      source_ref: 'refs/heads/main',
      sha: context.sha,
      ref: context.sha,
    },
  });
  assert.deepEqual(Object.keys(body.client_payload).sort(), ['ref', 'repository', 'schema_version', 'sha', 'source_ref']);
  assert.equal(Object.hasOwn(body.client_payload, 'digest'), false);
});

test('serializes the reviewed dispatch as one bounded non-redirecting POST', async () => {
  let observed;
  const api = new GitHubApi({
    token: `github_pat_${'x'.repeat(40)}`,
    fetchImpl: async (url, init) => {
      observed = { url: url.href, init };
      return new Response(null, { status: 204 });
    },
  });
  const body = createDispatchBody(producerContext());
  await api.request(`/repos/${DASHBOARD_REPOSITORY}/dispatches`, {
    method: 'POST',
    body,
    expectedStatus: 204,
  });
  assert.equal(observed.url, `https://api.github.com/repos/${DASHBOARD_REPOSITORY}/dispatches`);
  assert.equal(observed.init.method, 'POST');
  assert.equal(observed.init.redirect, 'error');
  assert.deepEqual(JSON.parse(observed.init.body), body);
});

test('rejects historical producer reruns before constructing a dispatch', () => {
  assert.throws(
    () => validateProducerContext(producerContext({ runAttempt: '2' })),
    /run attempt did not match/i,
  );
});

test('rejects producer refs, repositories, and API origins outside the reviewed boundary', () => {
  assert.throws(() => validateProducerContext(producerContext({ ref: 'refs/heads/release' })), /Producer ref/);
  assert.throws(() => validateProducerContext(producerContext({ repository: 'ScaleSmall/Other' })), /Producer repository/);
  assert.throws(() => validateProducerContext(producerContext({ apiUrl: 'https://example.invalid' })), /API origin/);
});

test('requires Dashboard to remain enabled with main as its exact default branch', () => {
  validateDashboardRepository({
    full_name: DASHBOARD_REPOSITORY,
    default_branch: 'main',
    archived: false,
    disabled: false,
  });
  assert.throws(() => validateDashboardRepository({
    full_name: DASHBOARD_REPOSITORY,
    default_branch: 'release',
    archived: false,
    disabled: false,
  }), /default branch/);
});

test('requires the exact reviewed Dashboard main commit', () => {
  validateDashboardMainRef({
    ref: 'refs/heads/main',
    object: { type: 'commit', sha: DASHBOARD_MAIN_SHA },
  });
  assert.throws(() => validateDashboardMainRef({
    ref: 'refs/heads/main',
    object: { type: 'commit', sha: '0'.repeat(40) },
  }), /main SHA/);
});

test('verifies exact consumer path, bytes, and SHA-256', () => {
  const bytes = Buffer.from('name: Update shared package\n', 'utf8');
  const expectedDigest = createHash('sha256').update(bytes).digest('hex');
  const file = {
    type: 'file',
    path: DASHBOARD_WORKFLOW_PATH,
    name: 'update-shared.yml',
    encoding: 'base64',
    sha: 'a'.repeat(40),
    size: bytes.byteLength,
    content: bytes.toString('base64'),
  };
  assert.deepEqual(validateDashboardWorkflowFile(file, expectedDigest), bytes);
  assert.throws(
    () => validateDashboardWorkflowFile(file, 'b'.repeat(64)),
    /consumer SHA-256/,
  );
});

test('requires the exact active consumer workflow marker', () => {
  const workflow = {
    id: 7001,
    name: 'Update shared package',
    path: DASHBOARD_WORKFLOW_PATH,
    state: 'active',
  };
  assert.equal(validateDashboardWorkflow(workflow), 7001);
  assert.throws(() => validateDashboardWorkflow({ ...workflow, state: 'disabled_manually' }), /workflow state/);
  assert.throws(() => validateDashboardWorkflow({ ...workflow, path: '.github/workflows/unsafe.yml' }), /workflow path/);
});

test('fails closed while any nonterminal historical consumer run remains', () => {
  for (const status of ['queued', 'in_progress', 'waiting', 'requested', 'pending']) {
    validateDrainedRunStatus({ total_count: 0, workflow_runs: [] }, status);
  }
  assert.throws(
    () => validateDrainedRunStatus({ total_count: 1, workflow_runs: [workflowRun()] }, 'queued'),
    /not drained/,
  );
});

test('accepts exactly one fresh attempt-one run on the reviewed consumer commit', () => {
  const run = workflowRun();
  assert.equal(validateFreshRunWitness(runsPayload([run]), witnessOptions()).id, run.id);
});

test('returns no witness when GitHub has not created a new run', () => {
  const oldRun = workflowRun({ id: 100 });
  assert.equal(validateFreshRunWitness(runsPayload([oldRun]), witnessOptions()), null);
});

test('rejects multiple new runs and stale or rerun witnesses', () => {
  assert.throws(
    () => validateFreshRunWitness(runsPayload([
      workflowRun(),
      workflowRun({ id: 9002, html_url: `https://github.com/${DASHBOARD_REPOSITORY}/actions/runs/9002` }),
    ]), witnessOptions()),
    /multiple new consumer runs/,
  );
  assert.throws(
    () => validateFreshRunWitness(runsPayload([
      workflowRun({ created_at: '2026-07-19T19:59:59.000Z' }),
    ]), witnessOptions()),
    /stale/,
  );
  assert.throws(
    () => validateFreshRunWitness(runsPayload([
      workflowRun({ run_attempt: 2 }),
    ]), witnessOptions()),
    /run attempt/,
  );
});

test('rejects a fresh run created from any unreviewed Dashboard commit', () => {
  assert.throws(
    () => validateFreshRunWitness(runsPayload([
      workflowRun({ head_sha: 'f'.repeat(40) }),
    ]), witnessOptions()),
    /head SHA/,
  );
});
