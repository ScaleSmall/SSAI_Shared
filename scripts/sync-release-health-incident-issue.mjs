import { pathToFileURL } from 'node:url';
import { parseReleaseHealthDeliveryIdentity } from './release-health-monitor-utils.mjs';

export const incidentIssueTitle = '[Automated] Scale Small AI release health incident';
export const incidentIssueLabel = 'release-health-monitor';
export const incidentIssueMarker = '<!-- ssai-release-health-monitor:v1 -->';

const expectedRepository = 'ScaleSmall/SSAI_Shared';
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

export function incidentDeliveryMarker(deliveryIdentity) {
  const exactIdentity = parseReleaseHealthDeliveryIdentity(deliveryIdentity).identity;
  return '<!-- ssai-release-health-monitor:delivery:v1 ' + exactIdentity + ' -->';
}

function validateInputs({ repository, incidentState, outcome, runId, deliveryIdentity }) {
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
  return Object.freeze({
    repository: expectedRepository,
    incidentState: normalizedIncidentState,
    outcome: normalizedOutcome,
    runId: exactRunId(runId),
    deliveryIdentity: exactDeliveryIdentity.identity,
    deliveryRunId: exactDeliveryIdentity.runId,
    deliveryRunAttempt: exactDeliveryIdentity.runAttempt,
  });
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

function incidentBody(deliveryIdentity, deliveryRunId, deliveryRunAttempt, incidentState) {
  const url = runUrl(deliveryRunId);
  const stateLine = incidentState === 'healthy'
    ? 'The protected release-health monitor has returned to healthy.'
    : 'The protected release-health monitor detected an incident that remains active.';
  return [
    incidentIssueMarker,
    incidentDeliveryMarker(deliveryIdentity),
    '',
    stateLine,
    '',
    'Authoritative state-transition run: ' + url,
    'Run attempt: ' + deliveryRunAttempt,
    '',
    'The public incident surface is intentionally aggregate-only. Use the protected run and operator evidence path for bounded diagnosis.',
    '',
    '_Managed automatically by `.github/workflows/release-health-monitor.yml`._',
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

export async function syncReleaseHealthIncidentIssue({
  api,
  repository,
  incidentState,
  outcome,
  runId,
  deliveryIdentity,
}) {
  if (typeof api !== 'function') throw new TypeError('api must be a function.');
  const input = validateInputs({ repository, incidentState, outcome, runId, deliveryIdentity });
  await ensureIncidentLabel(api);
  const encodedLabel = encodeURIComponent(incidentIssueLabel);
  const issues = await api('/repos/' + expectedRepository + '/issues?state=all&labels=' + encodedLabel
    + '&sort=created&direction=desc&per_page=100');
  const issue = selectManagedIncidentIssue(issues);
  const body = incidentBody(
    input.deliveryIdentity,
    input.deliveryRunId,
    input.deliveryRunAttempt,
    input.incidentState,
  );

  if (input.incidentState === 'incident') {
    if (!issue) {
      const created = await createWithReconciliation(api, body);
      return Object.freeze({ action: 'created', issueNumber: issueNumber(created) });
    }
    const number = issueNumber(issue);
    const state = issue.state === 'closed' ? 'open' : issue.state;
    if (state !== 'open') throw new Error('Managed incident issue has an invalid state.');
    if (issue.state === 'closed') {
      await api('/repos/' + expectedRepository + '/issues/' + number, {
        method: 'PATCH',
        body: { body, state: 'open', state_reason: 'reopened' },
      });
      return Object.freeze({ action: 'reopened', issueNumber: number });
    }
    if (String(issue.body || '') === body) {
      return Object.freeze({ action: 'already-open', issueNumber: number });
    }
    await api('/repos/' + expectedRepository + '/issues/' + number, {
      method: 'PATCH',
      body: { body },
    });
    return Object.freeze({ action: 'updated', issueNumber: number });
  }

  if (!issue) return Object.freeze({ action: 'already-closed', issueNumber: null });
  const number = issueNumber(issue);
  if (issue.state === 'closed') {
    if (String(issue.body || '') === body && issue.state_reason === 'completed') {
      return Object.freeze({ action: 'already-closed', issueNumber: number });
    }
    await api('/repos/' + expectedRepository + '/issues/' + number, {
      method: 'PATCH',
      body: {
        body,
        state: 'closed',
        state_reason: 'completed',
      },
    });
    return Object.freeze({ action: 'updated', issueNumber: number });
  }
  if (issue.state !== 'open') throw new Error('Managed incident issue has an invalid state.');
  await api('/repos/' + expectedRepository + '/issues/' + number, {
    method: 'PATCH',
    body: {
      body,
      state: 'closed',
      state_reason: 'completed',
    },
  });
  return Object.freeze({ action: 'closed', issueNumber: number });
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
    deliveryIdentity: environment.SSAI_RELEASE_MONITOR_DELIVERY_IDENTITY,
  });
  console.log(JSON.stringify({ delivery: result.action, issue_number: result.issueNumber }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runIncidentIssueSync().catch((error) => {
    console.error('::error::Release-health incident delivery failed closed.');
    if (String(process.env.GITHUB_ACTIONS || '').toLowerCase() !== 'true') {
      console.error(error instanceof Error ? error.stack || error.message : String(error));
    }
    process.exitCode = 1;
  });
}
