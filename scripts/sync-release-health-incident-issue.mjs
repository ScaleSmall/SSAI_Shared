import { pathToFileURL } from 'node:url';
import {
  parseReleaseHealthDeliveryIdentity,
  releaseHealthIncidentProducerPolicies,
  releaseHealthMonitorWorkflowIdentities,
  resolveReleaseHealthIncidentProducer,
} from './release-health-monitor-utils.mjs';

export const incidentIssueTitle = '[Automated] Scale Small AI release health incident';
export const incidentIssueLabel = 'release-health-monitor';
export const incidentIssueMarker = '<!-- ssai-release-health-monitor:v1 -->';
export const activeIncidentWorkflowId = releaseHealthIncidentProducerPolicies.nativeSchedule.workflowId;
export const rejectedCanaryWorkflowId = releaseHealthMonitorWorkflowIdentities.canary.workflowId;
export const rejectedFallbackWorkflowId = releaseHealthMonitorWorkflowIdentities.fallback.workflowId;

const expectedRepository = 'ScaleSmall/SSAI_Shared';
const expectedBranch = 'main';
const allowedIncidentWorkflowIds = new Set([
  activeIncidentWorkflowId,
]);
const allowedOutcomes = new Set([
  'new-or-worsened-incident',
  'known-incident-suppressed',
  'incident-improved-suppressed',
  'healthy',
]);
const allowedIncidentStates = new Set(['incident', 'healthy']);
const retryableStatuses = new Set([408, 425, 429, 500, 502, 503, 504]);
const retryDelaysMs = [1_000, 3_000];
const maximumRetryDelayMs = 30_000;

export class GitHubApiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = 'GitHubApiError';
    this.status = status;
  }
}

export class OperatorReconciliationRequiredError extends Error {
  constructor(message, options = undefined) {
    super('Operator reconciliation required: ' + message, options);
    this.name = 'OperatorReconciliationRequiredError';
  }
}

class GitHubPayloadError extends Error {
  constructor() {
    super('GitHub API response was not valid JSON.');
    this.name = 'GitHubPayloadError';
  }
}

function required(value, name) {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(name + ' is required.');
  return normalized;
}

function exactRunId(value) {
  const normalized = String(value || '').trim();
  if (!/^[1-9][0-9]{0,19}$/.test(normalized)) throw new Error('GITHUB_RUN_ID is invalid.');
  return normalized;
}

function exactRunAttempt(value, name = 'GITHUB_RUN_ATTEMPT') {
  const normalized = String(value || '').trim();
  if (!/^[1-9][0-9]{0,9}$/.test(normalized)
    || !Number.isSafeInteger(Number(normalized))) {
    throw new Error(name + ' is invalid.');
  }
  return normalized;
}

function exactWorkflowId(value, name = 'workflow ID') {
  const normalized = String(value ?? '').trim();
  if (!/^[1-9][0-9]{0,19}$/.test(normalized)
    || !Number.isSafeInteger(Number(normalized))) {
    throw new Error(name + ' is invalid.');
  }
  return Number(normalized);
}

function exactHeadSha(value, name = 'GITHUB_SHA') {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(normalized)) throw new Error(name + ' is invalid.');
  return normalized;
}

function exactCreatedAt(value) {
  const normalized = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(normalized)
    || !Number.isFinite(Date.parse(normalized))) {
    throw new Error('workflow run created_at is invalid.');
  }
  return normalized;
}

function producerPolicyForRun(workflowId, event) {
  const policy = Object.values(releaseHealthIncidentProducerPolicies)
    .find((candidate) => candidate.workflowId === workflowId);
  if (!policy) return null;
  return resolveReleaseHealthIncidentProducer({
    workflowId,
    path: policy.path,
    event,
  });
}

export function incidentDeliveryMarker(deliveryIdentity, workflowId = activeIncidentWorkflowId) {
  const exactIdentity = parseReleaseHealthDeliveryIdentity(deliveryIdentity).identity;
  const exactWorkflow = exactWorkflowId(workflowId);
  if (!allowedIncidentWorkflowIds.has(exactWorkflow)) {
    throw new Error('Incident delivery workflow ID is not registered.');
  }
  return '<!-- ssai-release-health-monitor:delivery:v2 workflow-'
    + exactWorkflow + ' ' + exactIdentity + ' -->';
}

function validateInputs({
  repository,
  incidentState,
  outcome,
  runId,
  runAttempt,
  headSha,
  deliveryIdentity,
}) {
  if (required(repository, 'GITHUB_REPOSITORY') !== expectedRepository) {
    throw new Error('Incident delivery is restricted to ' + expectedRepository + '.');
  }
  const normalizedOutcome = required(outcome, 'SSAI_RELEASE_MONITOR_NOTIFICATION_OUTCOME');
  if (!allowedOutcomes.has(normalizedOutcome)) {
    throw new Error('Incident delivery outcome is not actionable.');
  }
  const normalizedIncidentState = required(incidentState, 'SSAI_RELEASE_MONITOR_INCIDENT_STATE');
  if (!allowedIncidentStates.has(normalizedIncidentState)
    || (normalizedIncidentState === 'healthy' && normalizedOutcome !== 'healthy')
    || (normalizedIncidentState === 'incident' && normalizedOutcome === 'healthy')) {
    throw new Error('Incident delivery state and outcome are inconsistent.');
  }
  const exactDeliveryIdentity = parseReleaseHealthDeliveryIdentity(deliveryIdentity);
  const exactCurrentRunId = exactRunId(runId);
  const exactCurrentRunAttempt = exactRunAttempt(runAttempt);
  if (exactDeliveryIdentity.runId !== exactCurrentRunId) {
    throw new Error('Incident delivery identity is not bound to GITHUB_RUN_ID.');
  }
  if (exactDeliveryIdentity.runAttempt !== exactCurrentRunAttempt) {
    throw new Error('Incident delivery identity is not bound to GITHUB_RUN_ATTEMPT.');
  }
  return Object.freeze({
    repository: expectedRepository,
    incidentState: normalizedIncidentState,
    outcome: normalizedOutcome,
    runId: exactCurrentRunId,
    runAttempt: exactCurrentRunAttempt,
    headSha: exactHeadSha(headSha),
    deliveryIdentity: exactDeliveryIdentity.identity,
    deliveryRunId: exactDeliveryIdentity.runId,
    deliveryRunAttempt: exactDeliveryIdentity.runAttempt,
  });
}

function parseIssueDeliveryReference(body) {
  const deliveryLines = String(body || '').split(/\r?\n/)
    .filter((line) => line.includes('ssai-release-health-monitor:delivery:'));
  if (deliveryLines.length !== 1) {
    throw new OperatorReconciliationRequiredError(
      'the managed issue must contain exactly one authoritative delivery marker.',
    );
  }

  const line = deliveryLines[0].trim();
  const legacyMatch = /^<!-- ssai-release-health-monitor:delivery:v1 (run-[1-9][0-9]{0,19}-attempt-[1-9][0-9]{0,9}) -->$/.exec(line);
  if (legacyMatch) {
    try {
      const identity = parseReleaseHealthDeliveryIdentity(legacyMatch[1]);
      return Object.freeze({ version: 1, workflowId: null, ...identity });
    } catch (error) {
      throw new OperatorReconciliationRequiredError(
        'the managed issue legacy delivery marker is invalid.',
        { cause: error },
      );
    }
  }

  const currentMatch = /^<!-- ssai-release-health-monitor:delivery:v2 workflow-([1-9][0-9]{0,19}) (run-[1-9][0-9]{0,19}-attempt-[1-9][0-9]{0,9}) -->$/.exec(line);
  if (!currentMatch) {
    throw new OperatorReconciliationRequiredError(
      'the managed issue delivery marker is malformed or unsupported.',
    );
  }
  try {
    const workflowId = exactWorkflowId(currentMatch[1], 'managed issue workflow ID');
    if (!allowedIncidentWorkflowIds.has(workflowId)) {
      throw new Error('workflow identity is not registered.');
    }
    return Object.freeze({
      version: 2,
      workflowId,
      ...parseReleaseHealthDeliveryIdentity(currentMatch[2]),
    });
  } catch (error) {
    throw new OperatorReconciliationRequiredError(
      'the managed issue references an invalid or unregistered workflow identity.',
      { cause: error },
    );
  }
}

function normalizeRunMetadata(run, {
  expectedRunId,
  expectedRunAttempt,
  expectedWorkflowId = null,
  expectedHeadSha = null,
  prior = false,
}) {
  try {
    if (!run || typeof run !== 'object' || Array.isArray(run)) {
      throw new Error('workflow run payload is invalid.');
    }
    const id = exactRunId(run.id);
    const runAttempt = exactRunAttempt(run.run_attempt, 'workflow run attempt');
    const workflowId = exactWorkflowId(run.workflow_id);
    const headSha = exactHeadSha(run.head_sha, 'workflow run head SHA');
    const createdAt = exactCreatedAt(run.created_at);
    if (id !== expectedRunId || runAttempt !== expectedRunAttempt) {
      throw new Error('workflow run identity does not match its delivery marker.');
    }
    if (expectedWorkflowId === null) {
      if (!allowedIncidentWorkflowIds.has(workflowId)) {
        throw new Error('workflow run identity is not registered.');
      }
    } else if (workflowId !== expectedWorkflowId) {
      throw new Error('workflow run ID does not match its registered delivery identity.');
    }
    const producer = producerPolicyForRun(workflowId, run.event);
    if (!producer) throw new Error('workflow run producer is not authorized.');
    if (run.repository?.full_name !== expectedRepository) {
      throw new Error('workflow run repository is outside the managed boundary.');
    }
    if (run.head_branch !== expectedBranch) throw new Error('workflow run branch is not main.');
    if (expectedHeadSha !== null && headSha !== expectedHeadSha) {
      throw new Error('workflow run head SHA does not match GITHUB_SHA.');
    }
    return Object.freeze({ id, runAttempt, workflowId, headSha, createdAt, producer });
  } catch (error) {
    if (!prior) throw error;
    throw new OperatorReconciliationRequiredError(
      'prior authoritative workflow run metadata is invalid.',
      { cause: error },
    );
  }
}

async function fetchRunAttempt(api, runId, runAttempt, prior) {
  const path = '/repos/' + expectedRepository + '/actions/runs/' + runId
    + '/attempts/' + runAttempt;
  try {
    return await api(path);
  } catch (error) {
    if (prior && error instanceof GitHubApiError && error.status === 404) {
      throw new OperatorReconciliationRequiredError(
        'the prior authoritative workflow run is missing or deleted.',
        { cause: error },
      );
    }
    throw error;
  }
}

async function validateCandidateRun(api, input) {
  const run = await fetchRunAttempt(api, input.runId, input.runAttempt, false);
  return normalizeRunMetadata(run, {
    expectedRunId: input.runId,
    expectedRunAttempt: input.runAttempt,
    expectedWorkflowId: activeIncidentWorkflowId,
    expectedHeadSha: input.headSha,
  });
}

async function validatePriorRun(api, reference) {
  const run = await fetchRunAttempt(api, reference.runId, reference.runAttempt, true);
  return normalizeRunMetadata(run, {
    expectedRunId: reference.runId,
    expectedRunAttempt: reference.runAttempt,
    expectedWorkflowId: reference.workflowId,
    prior: true,
  });
}

function compareAuthoritativeRuns(candidate, prior) {
  const createdDelta = Date.parse(candidate.createdAt) - Date.parse(prior.createdAt);
  if (createdDelta !== 0) return createdDelta < 0 ? -1 : 1;
  const candidateId = BigInt(candidate.id);
  const priorId = BigInt(prior.id);
  if (candidateId !== priorId) return candidateId < priorId ? -1 : 1;
  const candidateAttempt = Number(candidate.runAttempt);
  const priorAttempt = Number(prior.runAttempt);
  if (candidateAttempt === priorAttempt) return 0;
  return candidateAttempt < priorAttempt ? -1 : 1;
}

function runUrl(runId) {
  return 'https://github.com/' + expectedRepository + '/actions/runs/' + runId;
}

function issueNumber(issue) {
  const number = Number(issue?.number);
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new Error('Managed incident issue number is invalid.');
  }
  return number;
}

function incidentBody(
  deliveryIdentity,
  deliveryRunId,
  deliveryRunAttempt,
  incidentState,
  producer,
) {
  if (!producer || typeof producer !== 'object') {
    throw new Error('Incident delivery producer is invalid.');
  }
  const url = runUrl(deliveryRunId);
  const stateLine = incidentState === 'healthy'
    ? 'The protected release-health monitor has returned to healthy.'
    : 'The protected release-health monitor detected an incident that remains active.';
  return [
    incidentIssueMarker,
    incidentDeliveryMarker(deliveryIdentity, producer.workflowId),
    '',
    stateLine,
    '',
    'Authoritative reconciliation run: ' + url,
    'Run attempt: ' + deliveryRunAttempt,
    '',
    'The public incident surface is intentionally aggregate-only. Use the protected run and operator evidence path for bounded diagnosis.',
    '',
    '_Managed automatically by `' + producer.path + '`._',
  ].join('\n');
}

export function selectManagedIncidentIssue(issues) {
  if (!Array.isArray(issues)) throw new TypeError('GitHub issues response must be an array.');
  if (issues.length >= 100) throw new Error('Incident issue lookup reached its bounded page limit.');
  if (issues.some((issue) => issue?.pull_request)) {
    throw new Error('The reserved incident label is attached to a pull request.');
  }
  const managed = issues.filter((issue) => (
    issue?.title === incidentIssueTitle
    && String(issue?.body || '').includes(incidentIssueMarker)
  ));
  if (managed.length !== issues.length) {
    throw new Error('The reserved incident label is attached to an unmanaged issue.');
  }
  if (managed.length > 1) throw new Error('Multiple managed incident issues exist.');
  return managed[0] || null;
}

function issueHasManagedLabel(issue) {
  return Array.isArray(issue?.labels) && issue.labels.some((label) => (
    (typeof label === 'string' ? label : label?.name) === incidentIssueLabel
  ));
}

function validateExactManagedIssue(issue, expectedNumber) {
  let number;
  try {
    number = issueNumber(issue);
  } catch (error) {
    throw new OperatorReconciliationRequiredError(
      'the exact managed issue identity is invalid.',
      { cause: error },
    );
  }
  if (number !== expectedNumber
    || issue?.pull_request
    || issue?.title !== incidentIssueTitle
    || !String(issue?.body || '').includes(incidentIssueMarker)
    || !issueHasManagedLabel(issue)
    || !['open', 'closed'].includes(issue?.state)) {
    throw new OperatorReconciliationRequiredError(
      'the exact managed issue identity, label, or state changed before mutation.',
    );
  }
  return Object.freeze({ ...issue, number });
}

function exactDesiredIssueState(issue, input, body) {
  const expectedState = input.incidentState === 'incident' ? 'open' : 'closed';
  return String(issue.body || '') === body
    && issue.state === expectedState
    && (expectedState !== 'closed' || issue.state_reason === 'completed');
}

function authoritativeDeliveryMarkerLine(issue) {
  return String(issue?.body || '').split(/\r?\n/)
    .find((line) => line.includes('ssai-release-health-monitor:delivery:'))?.trim() || '';
}

function canonicalIssueLabelIdentity(issue) {
  if (!Array.isArray(issue?.labels)) return '';
  return JSON.stringify(issue.labels.map((label) => (
    typeof label === 'string'
      ? { id: null, nodeId: '', name: label }
      : {
        id: Number.isSafeInteger(Number(label?.id)) ? Number(label.id) : null,
        nodeId: String(label?.node_id || ''),
        name: String(label?.name || ''),
      }
  )).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))));
}

function assertSameMarkerSnapshotUnchanged(initialIssue, exactIssue) {
  if (authoritativeDeliveryMarkerLine(initialIssue) !== authoritativeDeliveryMarkerLine(exactIssue)) return;
  if (String(initialIssue?.body || '') !== String(exactIssue?.body || '')
    || initialIssue?.state !== exactIssue?.state
    || String(initialIssue?.state_reason || '') !== String(exactIssue?.state_reason || '')
    || initialIssue?.title !== exactIssue?.title
    || canonicalIssueLabelIdentity(initialIssue) !== canonicalIssueLabelIdentity(exactIssue)
    || String(initialIssue?.updated_at || '') !== String(exactIssue?.updated_at || '')) {
    throw new OperatorReconciliationRequiredError(
      'the managed issue changed without an authoritative delivery-marker advance.',
    );
  }
}

async function revalidateManagedIssueBeforePatch(api, initialIssue, number, candidateRun, input, body) {
  const issuePath = '/repos/' + expectedRepository + '/issues/' + number;
  const initialReference = parseIssueDeliveryReference(initialIssue.body);
  const initialRun = await validatePriorRun(api, initialReference);
  let exactIssue = validateExactManagedIssue(await api(issuePath), number);
  let priorReference = initialReference;
  let priorRun = initialRun;
  if (authoritativeDeliveryMarkerLine(initialIssue) === authoritativeDeliveryMarkerLine(exactIssue)) {
    assertSameMarkerSnapshotUnchanged(initialIssue, exactIssue);
  } else {
    priorReference = parseIssueDeliveryReference(exactIssue.body);
    priorRun = await validatePriorRun(api, priorReference);
    const prefetchedIssue = exactIssue;
    exactIssue = validateExactManagedIssue(await api(issuePath), number);
    if (authoritativeDeliveryMarkerLine(prefetchedIssue) !== authoritativeDeliveryMarkerLine(exactIssue)) {
      throw new OperatorReconciliationRequiredError(
        'the authoritative delivery marker advanced again during bounded revalidation.',
      );
    }
    assertSameMarkerSnapshotUnchanged(prefetchedIssue, exactIssue);
  }
  const order = compareAuthoritativeRuns(candidateRun, priorRun);
  if (order < 0) {
    return Object.freeze({
      issue: exactIssue,
      terminal: Object.freeze({ action: 'stale-suppressed', issueNumber: number }),
    });
  }
  if (order === 0 && priorReference.version === 2) {
    if (!exactDesiredIssueState(exactIssue, input, body)) {
      throw new OperatorReconciliationRequiredError(
        'the exact authoritative delivery marker conflicts with managed issue state.',
      );
    }
    return Object.freeze({
      issue: exactIssue,
      terminal: Object.freeze({
        action: input.incidentState === 'incident' ? 'already-open' : 'already-closed',
        issueNumber: number,
      }),
    });
  }
  return Object.freeze({ issue: exactIssue, terminal: null });
}

export async function syncReleaseHealthIncidentIssue({
  api,
  repository,
  incidentState,
  outcome,
  runId,
  runAttempt,
  headSha,
  deliveryIdentity,
}) {
  if (typeof api !== 'function') throw new TypeError('api must be a function.');
  const input = validateInputs({
    repository,
    incidentState,
    outcome,
    runId,
    runAttempt,
    headSha,
    deliveryIdentity,
  });
  const candidateRun = await validateCandidateRun(api, input);
  const encodedLabel = encodeURIComponent(incidentIssueLabel);
  const issues = await api('/repos/' + expectedRepository + '/issues?state=all&labels=' + encodedLabel
    + '&sort=created&direction=desc&per_page=100');
  const issue = selectManagedIncidentIssue(issues);
  const body = incidentBody(
    input.deliveryIdentity,
    input.deliveryRunId,
    input.deliveryRunAttempt,
    input.incidentState,
    candidateRun.producer,
  );

  if (!issue) {
    if (input.incidentState === 'healthy') {
      return Object.freeze({ action: 'already-closed', issueNumber: null });
    }
    await ensureIncidentLabel(api);
    const created = await createWithReconciliation(api, body);
    return Object.freeze({ action: 'created', issueNumber: issueNumber(created) });
  }

  const number = issueNumber(issue);
  await ensureIncidentLabel(api);
  const revalidated = await revalidateManagedIssueBeforePatch(
    api,
    issue,
    number,
    candidateRun,
    input,
    body,
  );
  if (revalidated.terminal) return revalidated.terminal;
  if (input.incidentState === 'incident') {
    const action = revalidated.issue.state === 'closed' ? 'reopened' : 'updated';
    await api('/repos/' + expectedRepository + '/issues/' + number, {
      method: 'PATCH',
      body: revalidated.issue.state === 'closed'
        ? { body, state: 'open', state_reason: 'reopened' }
        : { body, state: 'open' },
    });
    return Object.freeze({ action, issueNumber: number });
  }
  const action = revalidated.issue.state === 'open' ? 'closed' : 'updated';
  await api('/repos/' + expectedRepository + '/issues/' + number, {
    method: 'PATCH',
    body: {
      body,
      state: 'closed',
      state_reason: 'completed',
    },
  });
  return Object.freeze({ action, issueNumber: number });
}

async function ensureIncidentLabel(api) {
  const labelPath = '/repos/' + expectedRepository + '/labels/' + encodeURIComponent(incidentIssueLabel);
  try {
    const label = await api(labelPath);
    if (label?.name !== incidentIssueLabel) throw new Error('Incident label identity is invalid.');
    return;
  } catch (error) {
    if (!(error instanceof GitHubApiError) || error.status !== 404) throw error;
  }

  try {
    const created = await api('/repos/' + expectedRepository + '/labels', {
      method: 'POST',
      body: {
        name: incidentIssueLabel,
        color: 'B60205',
        description: 'Managed release-health incident delivery',
      },
      retry: false,
    });
    if (created?.name !== incidentIssueLabel) throw new Error('Created incident label identity is invalid.');
  } catch (error) {
    const reconciled = await api(labelPath);
    if (reconciled?.name !== incidentIssueLabel) throw error;
  }
}

async function createWithReconciliation(api, body) {
  try {
    return await api('/repos/' + expectedRepository + '/issues', {
      method: 'POST',
      body: { title: incidentIssueTitle, body, labels: [incidentIssueLabel] },
      retry: false,
    });
  } catch (error) {
    const issues = await api('/repos/' + expectedRepository + '/issues?state=all&labels='
      + encodeURIComponent(incidentIssueLabel) + '&sort=created&direction=desc&per_page=100');
    const issue = selectManagedIncidentIssue(issues);
    if (issue && String(issue.body || '') === body) return issue;
    throw error;
  }
}

function retryAfterDelayMs(response, fallbackMs, nowMs, randomValue) {
  const retryAfter = String(response.headers.get('retry-after') || '').trim();
  const reset = String(response.headers.get('x-ratelimit-reset') || '').trim();
  let requestedDelayMs = null;
  if (/^\d+$/.test(retryAfter)) {
    requestedDelayMs = Number(retryAfter) * 1_000;
  } else if (retryAfter) {
    const retryAt = Date.parse(retryAfter);
    if (Number.isFinite(retryAt)) requestedDelayMs = Math.max(0, retryAt - nowMs);
  } else if (/^\d+$/.test(reset)) {
    requestedDelayMs = Math.max(0, Number(reset) * 1_000 - nowMs);
  }
  const jitterMs = Number.isFinite(randomValue) && randomValue >= 0 && randomValue < 1
    ? Math.floor(randomValue * 251)
    : 0;
  return Math.min(maximumRetryDelayMs, Math.max(fallbackMs, requestedDelayMs || 0) + jitterMs);
}

function isHeaderConfirmedRateLimit(response) {
  if (response.status !== 403) return false;
  return Boolean(String(response.headers.get('retry-after') || '').trim())
    || (String(response.headers.get('x-ratelimit-remaining') || '').trim() === '0'
      && /^\d+$/.test(String(response.headers.get('x-ratelimit-reset') || '').trim()));
}

export function createGitHubApi({
  token,
  apiUrl = 'https://api.github.com',
  fetchImpl = fetch,
  sleepImpl = (delayMs) => new Promise((resolveDelay) => setTimeout(resolveDelay, delayMs)),
  randomImpl = Math.random,
  nowImpl = Date.now,
}) {
  const authToken = required(token, 'GITHUB_TOKEN');
  if (authToken.length < 20) throw new Error('GITHUB_TOKEN is invalid.');
  if (apiUrl !== 'https://api.github.com') throw new Error('GITHUB_API_URL is not approved.');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a function.');
  if (typeof sleepImpl !== 'function' || typeof randomImpl !== 'function' || typeof nowImpl !== 'function') {
    throw new TypeError('GitHub API retry dependencies must be functions.');
  }

  return async function api(path, options = {}) {
    if (!/^\/repos\/ScaleSmall\/SSAI_Shared\//.test(String(path || ''))) {
      throw new Error('GitHub API path is outside the repository boundary.');
    }
    const method = String(options.method || 'GET').toUpperCase();
    if (!['GET', 'POST', 'PATCH'].includes(method)) throw new Error('GitHub API method is not approved.');
    const attempts = options.retry === false || method === 'POST' ? 1 : retryDelaysMs.length + 1;
    let lastError;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        const response = await fetchImpl(apiUrl + path, {
          method,
          headers: {
            Accept: 'application/vnd.github+json',
            Authorization: 'Bearer ' + authToken,
            'X-GitHub-Api-Version': '2022-11-28',
            ...(options.body ? { 'Content-Type': 'application/json' } : {}),
          },
          body: options.body ? JSON.stringify(options.body) : undefined,
          signal: AbortSignal.timeout(15_000),
        });
        if (response.ok) {
          const text = await response.text();
          try {
            return text ? JSON.parse(text) : null;
          } catch {
            throw new GitHubPayloadError();
          }
        }
        const error = new GitHubApiError('GitHub API request failed with HTTP ' + response.status + '.', response.status);
        const retryable = retryableStatuses.has(response.status) || isHeaderConfirmedRateLimit(response);
        if (!retryable || attempt === attempts - 1) throw error;
        lastError = error;
        await sleepImpl(retryAfterDelayMs(response, retryDelaysMs[attempt], nowImpl(), randomImpl()));
        continue;
      } catch (error) {
        if (error instanceof GitHubApiError || error instanceof GitHubPayloadError) throw error;
        lastError = error;
        if (attempt === attempts - 1) throw error;
      }
      await sleepImpl(Math.min(maximumRetryDelayMs, retryDelaysMs[attempt]
        + Math.floor(Math.max(0, Math.min(0.999999, Number(randomImpl()) || 0)) * 251)));
    }
    throw lastError || new Error('GitHub API request failed.');
  };
}

export async function runIncidentIssueSync(environment = process.env) {
  const api = createGitHubApi({
    token: environment.GITHUB_TOKEN,
    apiUrl: String(environment.GITHUB_API_URL || 'https://api.github.com'),
  });
  const result = await syncReleaseHealthIncidentIssue({
    api,
    repository: environment.GITHUB_REPOSITORY,
    incidentState: environment.SSAI_RELEASE_MONITOR_INCIDENT_STATE,
    outcome: environment.SSAI_RELEASE_MONITOR_NOTIFICATION_OUTCOME,
    runId: environment.GITHUB_RUN_ID,
    runAttempt: environment.GITHUB_RUN_ATTEMPT,
    headSha: environment.GITHUB_SHA,
    deliveryIdentity: environment.SSAI_RELEASE_MONITOR_DELIVERY_IDENTITY,
  });
  console.log(JSON.stringify({ delivery: result.action, issue_number: result.issueNumber }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runIncidentIssueSync().catch((error) => {
    console.error(error instanceof OperatorReconciliationRequiredError
      ? '::error::Release-health incident delivery requires explicit operator reconciliation.'
      : '::error::Release-health incident delivery failed closed.');
    if (String(process.env.GITHUB_ACTIONS || '').toLowerCase() !== 'true') {
      console.error(error instanceof Error ? error.stack || error.message : String(error));
    }
    process.exitCode = 1;
  });
}
