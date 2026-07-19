#!/usr/bin/env node
import { createHash } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const DASHBOARD_REPOSITORY = 'ScaleSmall/SSAI_Dashboard';
export const DASHBOARD_DEFAULT_BRANCH = 'main';
export const DASHBOARD_MAIN_SHA = 'ca31240527c5a60d3041f8efa41cb8767654db1a';
export const DASHBOARD_WORKFLOW_PATH = '.github/workflows/update-shared.yml';
export const DASHBOARD_WORKFLOW_NAME = 'Update shared package';
export const DASHBOARD_WORKFLOW_SHA256 = '221bcc96c02dc1f272f8aee663b0d20e71f4cc345b414bbbb835a674a72b3af1';
export const SHARED_REPOSITORY = 'ScaleSmall/SSAI_Shared';
export const SHARED_MAIN_REF = 'refs/heads/main';
export const DISPATCH_EVENT_TYPE = 'shared-updated';
export const DISPATCH_SCHEMA_VERSION = 2;

const GITHUB_API_BASE = 'https://api.github.com';
const API_VERSION = '2022-11-28';
const API_TIMEOUT_MS = 20_000;
const MAX_API_RESPONSE_BYTES = 2 * 1024 * 1024;
const WITNESS_TIMEOUT_MS = 120_000;
const WITNESS_POLL_MS = 5_000;
const WITNESS_SETTLE_MS = 5_000;
const ACTIVE_RUN_STATUSES = Object.freeze(['queued', 'in_progress', 'waiting', 'requested', 'pending']);
const OBSERVED_RUN_STATUSES = new Set([
  ...ACTIVE_RUN_STATUSES,
  'completed',
]);

const fail = (message) => {
  throw new Error(message);
};

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isLowerHex = (value, length) => typeof value === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(value);
const isPositiveSafeInteger = (value) => Number.isSafeInteger(value) && value > 0;

const requireObject = (value, label) => {
  if (!isObject(value)) fail(`${label} must be an object`);
  return value;
};

const requireEqual = (actual, expected, label) => {
  if (actual !== expected) fail(`${label} did not match the reviewed release contract`);
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const decodeCanonicalBase64 = (value) => {
  if (typeof value !== 'string') fail('Dashboard consumer workflow content is not base64 text');
  const compact = value.replace(/[\r\n]/g, '');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact)) {
    fail('Dashboard consumer workflow content has invalid base64 encoding');
  }
  const bytes = Buffer.from(compact, 'base64');
  if (bytes.toString('base64') !== compact) fail('Dashboard consumer workflow content is not canonical base64');
  return bytes;
};

async function readBoundedText(response) {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_API_RESPONSE_BYTES) {
    fail('GitHub API response exceeded the bounded response limit');
  }
  if (!response.body) return '';

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_API_RESPONSE_BYTES) {
      await reader.cancel();
      fail('GitHub API response exceeded the bounded response limit');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total).toString('utf8');
}

export class GitHubApi {
  #token;
  #fetch;

  constructor({ token, fetchImpl = globalThis.fetch } = {}) {
    if (typeof token !== 'string' || token.length < 20 || token.trim() !== token || /[\r\n]/.test(token)) {
      fail('The dedicated Dashboard dispatch token is not configured correctly');
    }
    if (typeof fetchImpl !== 'function') fail('A fetch implementation is required');
    this.#token = token;
    this.#fetch = fetchImpl;
  }

  async request(apiPath, { method = 'GET', body, expectedStatus = 200 } = {}) {
    if (typeof apiPath !== 'string' || !apiPath.startsWith('/')) fail('GitHub API path must be repository-relative');
    const url = new URL(apiPath, GITHUB_API_BASE);
    if (url.origin !== GITHUB_API_BASE || !url.pathname.startsWith('/')) fail('Refusing an unexpected GitHub API target');

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
    let response;
    try {
      response = await this.#fetch(url, {
        method,
        redirect: 'error',
        signal: controller.signal,
        headers: {
          accept: 'application/vnd.github+json',
          authorization: `Bearer ${this.#token}`,
          'content-type': 'application/json',
          'user-agent': 'ScaleSmall-SSAI-Shared-propagation',
          'x-github-api-version': API_VERSION,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      const reason = error?.name === 'AbortError' ? 'timed out' : 'failed before a response was proved';
      fail(`GitHub API ${method} ${url.pathname} ${reason}`);
    } finally {
      clearTimeout(timeout);
    }

    const text = await readBoundedText(response);
    if (response.status !== expectedStatus) {
      fail(`GitHub API ${method} ${url.pathname} returned HTTP ${response.status}; no release action was proved`);
    }
    if (expectedStatus === 204) {
      if (text.length !== 0) fail(`GitHub API ${method} ${url.pathname} returned an unexpected response body`);
      return null;
    }
    if (!text) fail(`GitHub API ${method} ${url.pathname} returned an empty response`);
    try {
      return JSON.parse(text);
    } catch {
      fail(`GitHub API ${method} ${url.pathname} returned invalid JSON`);
    }
  }
}

export function validateProducerContext(context) {
  requireObject(context, 'Producer context');
  requireEqual(context.repository, SHARED_REPOSITORY, 'Producer repository');
  requireEqual(context.ref, SHARED_MAIN_REF, 'Producer ref');
  if (!isLowerHex(context.sha, 40)) fail('Producer SHA must be one lowercase immutable commit');
  if (!['push', 'workflow_dispatch'].includes(context.eventName)) fail('Producer event must be a fresh main push or workflow_dispatch');
  requireEqual(context.runAttempt, '1', 'Producer run attempt');
  requireEqual(context.apiUrl, GITHUB_API_BASE, 'GitHub API origin');
  return Object.freeze({ ...context });
}

export function createDispatchBody(context) {
  const source = validateProducerContext(context);
  return {
    event_type: DISPATCH_EVENT_TYPE,
    client_payload: {
      schema_version: DISPATCH_SCHEMA_VERSION,
      repository: source.repository,
      source_ref: source.ref,
      sha: source.sha,
      ref: source.sha,
    },
  };
}

export function validateDashboardRepository(metadata) {
  const repository = requireObject(metadata, 'Dashboard repository metadata');
  requireEqual(repository.full_name, DASHBOARD_REPOSITORY, 'Dashboard repository identity');
  requireEqual(repository.default_branch, DASHBOARD_DEFAULT_BRANCH, 'Dashboard default branch');
  requireEqual(repository.archived, false, 'Dashboard archived state');
  requireEqual(repository.disabled, false, 'Dashboard disabled state');
}

export function validateDashboardMainRef(refPayload) {
  const ref = requireObject(refPayload, 'Dashboard main ref');
  const object = requireObject(ref.object, 'Dashboard main ref object');
  requireEqual(ref.ref, `refs/heads/${DASHBOARD_DEFAULT_BRANCH}`, 'Dashboard main ref name');
  requireEqual(object.type, 'commit', 'Dashboard main ref type');
  requireEqual(object.sha, DASHBOARD_MAIN_SHA, 'Dashboard main SHA');
}

export function validateDashboardWorkflowFile(filePayload, expectedSha256 = DASHBOARD_WORKFLOW_SHA256) {
  if (!isLowerHex(expectedSha256, 64)) fail('Expected Dashboard consumer SHA-256 is invalid');
  const file = requireObject(filePayload, 'Dashboard consumer workflow file');
  requireEqual(file.type, 'file', 'Dashboard consumer object type');
  requireEqual(file.path, DASHBOARD_WORKFLOW_PATH, 'Dashboard consumer path');
  requireEqual(file.name, path.posix.basename(DASHBOARD_WORKFLOW_PATH), 'Dashboard consumer filename');
  requireEqual(file.encoding, 'base64', 'Dashboard consumer encoding');
  if (!isLowerHex(file.sha, 40)) fail('Dashboard consumer Git blob SHA is invalid');
  const bytes = decodeCanonicalBase64(file.content);
  requireEqual(file.size, bytes.byteLength, 'Dashboard consumer byte length');
  requireEqual(sha256(bytes), expectedSha256, 'Dashboard consumer SHA-256');
  return bytes;
}

export function validateDashboardWorkflow(metadata) {
  const workflow = requireObject(metadata, 'Dashboard consumer workflow metadata');
  if (!isPositiveSafeInteger(workflow.id)) fail('Dashboard consumer workflow id is invalid');
  requireEqual(workflow.name, DASHBOARD_WORKFLOW_NAME, 'Dashboard consumer workflow name');
  requireEqual(workflow.path, DASHBOARD_WORKFLOW_PATH, 'Dashboard consumer workflow path');
  requireEqual(workflow.state, 'active', 'Dashboard consumer workflow state');
  return workflow.id;
}

export function validateDrainedRunStatus(payload, status) {
  if (!ACTIVE_RUN_STATUSES.includes(status)) fail('Unknown nonterminal workflow-run status');
  const result = requireObject(payload, `Dashboard ${status} run inventory`);
  if (!Number.isSafeInteger(result.total_count) || result.total_count < 0 || !Array.isArray(result.workflow_runs)) {
    fail(`Dashboard ${status} run inventory is malformed`);
  }
  if (result.total_count !== 0 || result.workflow_runs.length !== 0) {
    fail(`Dashboard consumer is not drained: ${status} workflow runs still exist`);
  }
}

export function validateRecentRuns(payload) {
  const result = requireObject(payload, 'Dashboard repository_dispatch run inventory');
  if (!Number.isSafeInteger(result.total_count) || result.total_count < 0 || !Array.isArray(result.workflow_runs)) {
    fail('Dashboard repository_dispatch run inventory is malformed');
  }
  const ids = new Set();
  for (const run of result.workflow_runs) {
    requireObject(run, 'Dashboard workflow run');
    if (!isPositiveSafeInteger(run.id) || ids.has(run.id)) fail('Dashboard workflow run inventory contains an invalid or duplicate id');
    ids.add(run.id);
  }
  return result.workflow_runs;
}

export function validateFreshRunWitness(runsPayload, { baselineIds, dispatchStartedAt, workflowId }) {
  if (!(baselineIds instanceof Set)) fail('Dashboard baseline run ids must be a Set');
  if (!isPositiveSafeInteger(workflowId)) fail('Dashboard witness workflow id is invalid');
  const dispatchStartedMs = Date.parse(dispatchStartedAt);
  if (!Number.isFinite(dispatchStartedMs)) fail('Dashboard dispatch start time is invalid');

  const newRuns = validateRecentRuns(runsPayload).filter((run) => !baselineIds.has(run.id));
  if (newRuns.length === 0) return null;
  if (newRuns.length !== 1) fail('Dashboard dispatch produced multiple new consumer runs');

  const run = newRuns[0];
  const createdAtMs = Date.parse(run.created_at);
  if (!Number.isFinite(createdAtMs) || createdAtMs < dispatchStartedMs) fail('Dashboard consumer witness is stale');
  requireEqual(run.workflow_id, workflowId, 'Dashboard consumer witness workflow id');
  requireEqual(run.event, 'repository_dispatch', 'Dashboard consumer witness event');
  requireEqual(run.path, DASHBOARD_WORKFLOW_PATH, 'Dashboard consumer witness path');
  requireEqual(run.head_branch, DASHBOARD_DEFAULT_BRANCH, 'Dashboard consumer witness branch');
  requireEqual(run.head_sha, DASHBOARD_MAIN_SHA, 'Dashboard consumer witness head SHA');
  requireEqual(run.run_attempt, 1, 'Dashboard consumer witness run attempt');
  if (!OBSERVED_RUN_STATUSES.has(run.status)) fail('Dashboard consumer witness status is invalid');
  requireEqual(requireObject(run.repository, 'Dashboard consumer witness repository').full_name, DASHBOARD_REPOSITORY, 'Dashboard consumer witness repository');
  requireEqual(requireObject(run.head_repository, 'Dashboard consumer witness head repository').full_name, DASHBOARD_REPOSITORY, 'Dashboard consumer witness head repository');
  if (typeof run.html_url !== 'string' || !run.html_url.startsWith(`https://github.com/${DASHBOARD_REPOSITORY}/actions/runs/`)) {
    fail('Dashboard consumer witness URL is invalid');
  }
  return run;
}

const repoApiPath = (suffix) => `/repos/${DASHBOARD_REPOSITORY}${suffix}`;
const workflowApiPath = (workflowId, suffix = '') => repoApiPath(`/actions/workflows/${workflowId}${suffix}`);

async function readDashboardMain(api) {
  const payload = await api.request(repoApiPath(`/git/ref/heads/${DASHBOARD_DEFAULT_BRANCH}`));
  validateDashboardMainRef(payload);
}

async function readDashboardWorkflow(api) {
  const payload = await api.request(repoApiPath(`/actions/workflows/${encodeURIComponent(path.posix.basename(DASHBOARD_WORKFLOW_PATH))}`));
  return validateDashboardWorkflow(payload);
}

async function assertDashboardDrained(api, workflowId) {
  for (const status of ACTIVE_RUN_STATUSES) {
    const payload = await api.request(workflowApiPath(workflowId, `/runs?status=${encodeURIComponent(status)}&per_page=1`));
    validateDrainedRunStatus(payload, status);
  }
}

async function readRecentDispatchRuns(api, workflowId) {
  return api.request(workflowApiPath(workflowId, '/runs?event=repository_dispatch&per_page=100'));
}

export async function attestDashboardConsumer(api) {
  validateDashboardRepository(await api.request(repoApiPath('')));
  await readDashboardMain(api);
  const workflowFile = await api.request(
    repoApiPath(`/contents/${DASHBOARD_WORKFLOW_PATH}?ref=${encodeURIComponent(DASHBOARD_MAIN_SHA)}`),
  );
  validateDashboardWorkflowFile(workflowFile);
  const workflowId = await readDashboardWorkflow(api);
  await assertDashboardDrained(api, workflowId);

  const baselinePayload = await readRecentDispatchRuns(api, workflowId);
  const baselineRuns = validateRecentRuns(baselinePayload);
  const baselineIds = new Set(baselineRuns.map((run) => run.id));

  // Recheck all mutable target state immediately before the dispatch. The file
  // itself is immutable at DASHBOARD_MAIN_SHA and was already digest-verified.
  await readDashboardMain(api);
  const recheckedWorkflowId = await readDashboardWorkflow(api);
  requireEqual(recheckedWorkflowId, workflowId, 'Dashboard consumer workflow id recheck');
  await assertDashboardDrained(api, workflowId);

  return { workflowId, baselineIds };
}

export async function dispatchDashboardUpdate({
  api,
  context,
  now = Date.now,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  witnessTimeoutMs = WITNESS_TIMEOUT_MS,
  witnessPollMs = WITNESS_POLL_MS,
  witnessSettleMs = WITNESS_SETTLE_MS,
}) {
  if (!api || typeof api.request !== 'function') fail('GitHub API client is required');
  if (![witnessTimeoutMs, witnessPollMs, witnessSettleMs].every((value) => Number.isSafeInteger(value) && value >= 0)) {
    fail('Dashboard witness timing bounds are invalid');
  }

  const body = createDispatchBody(context);
  const { workflowId, baselineIds } = await attestDashboardConsumer(api);
  const dispatchStartedMs = Math.floor(now() / 1000) * 1000;
  const dispatchStartedAt = new Date(dispatchStartedMs).toISOString();

  // This POST is deliberately never retried. A transport failure is an
  // uncertain outcome and must be reconciled through a new, non-rerun release.
  await api.request(repoApiPath('/dispatches'), {
    method: 'POST',
    body,
    expectedStatus: 204,
  });

  const deadline = now() + witnessTimeoutMs;
  let witness = null;
  while (now() <= deadline) {
    witness = validateFreshRunWitness(await readRecentDispatchRuns(api, workflowId), {
      baselineIds,
      dispatchStartedAt,
      workflowId,
    });
    if (witness) break;
    await sleep(witnessPollMs);
  }
  if (!witness) fail('Dashboard accepted the dispatch but no fresh consumer run was witnessed');

  await sleep(witnessSettleMs);
  const settledWitness = validateFreshRunWitness(await readRecentDispatchRuns(api, workflowId), {
    baselineIds,
    dispatchStartedAt,
    workflowId,
  });
  if (!settledWitness || settledWitness.id !== witness.id) {
    fail('Dashboard consumer witness did not remain unique during the settling check');
  }
  return settledWitness;
}

function contextFromEnvironment(environment) {
  return {
    repository: environment.GITHUB_REPOSITORY,
    ref: environment.GITHUB_REF,
    sha: environment.GITHUB_SHA,
    eventName: environment.GITHUB_EVENT_NAME,
    runAttempt: environment.GITHUB_RUN_ATTEMPT,
    apiUrl: environment.GITHUB_API_URL,
  };
}

async function main() {
  const token = process.env.SSAI_DASHBOARD_DISPATCH_TOKEN;
  delete process.env.SSAI_DASHBOARD_DISPATCH_TOKEN;
  const api = new GitHubApi({ token });
  const witness = await dispatchDashboardUpdate({
    api,
    context: contextFromEnvironment(process.env),
  });
  console.log(`Dashboard v2 dispatch was accepted and fresh run ${witness.id} was witnessed: ${witness.html_url}`);
}

const isDirectExecution = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isDirectExecution) {
  main().catch((error) => {
    console.error(`::error::${error instanceof Error ? error.message : 'Dashboard propagation failed closed'}`);
    process.exitCode = 1;
  });
}
