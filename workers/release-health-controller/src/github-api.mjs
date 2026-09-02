const API = 'https://api.github.com';
const VERSION = '2026-03-10';
const MAX_BYTES = 1_000_000;
export const GITHUB_USER_AGENT = 'ScaleSmall-SSAI-Release-Health-Controller/1.0';
export const WORKFLOW_RUN_PAGE_SIZE = 25;
const workflowIds = new Set(['315630665', '344135917', '344170407']);
const bodyTransportFailureBrand = Symbol('github-body-transport-failure');
const queries = new Set([
  `event=schedule&branch=main&per_page=${WORKFLOW_RUN_PAGE_SIZE}`,
  `event=workflow_dispatch&branch=main&per_page=${WORKFLOW_RUN_PAGE_SIZE}`,
]);

function exactReadPath(path) {
  if (path === '/repos/ScaleSmall/SSAI_Shared/commits/main') return 'commit';
  const match = /^\/repos\/ScaleSmall\/SSAI_Shared\/actions\/workflows\/(\d+)\/runs\?([^#]+)$/.exec(path);
  if (!match || !workflowIds.has(match[1]) || !queries.has(match[2])) {
    throw new Error('GitHub read endpoint is not allowed.');
  }
  return 'workflow-runs';
}

function immutableHeaders(token, contentType = false) {
  if (typeof token !== 'string' || token.length < 8 || token.length > 4096 || /[\r\n]/.test(token)) {
    throw new Error('GitHub credential is invalid.');
  }
  return Object.freeze({
    Accept: 'application/vnd.github+json',
    'Accept-Encoding': 'identity',
    Authorization: `Bearer ${token}`,
    'User-Agent': GITHUB_USER_AGENT,
    'X-GitHub-Api-Version': VERSION,
    ...(contentType ? { 'Content-Type': 'application/json' } : {}),
  });
}

function bodyTransportFailure() {
  const failure = Object.assign(
    new Error('GitHub response body transport failed closed.'),
    { failureClass: 'transport' },
  );
  Object.defineProperty(failure, bodyTransportFailureBrand, { value: true });
  return failure;
}

function canonicalContentLength(response, maximum) {
  const value = response.headers.get('content-length');
  if (value === null || !/^(?:0|[1-9][0-9]*)$/.test(value)) return null;
  const length = Number(value);
  return Number.isSafeInteger(length) && length <= maximum ? length : null;
}

function responseConsumer(response, attempt, maximum) {
  return attempt === 3 && canonicalContentLength(response, maximum) !== null
    ? 'native-buffer'
    : 'stream';
}

async function readBytes(response, maximum = MAX_BYTES, consumer = 'stream') {
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > maximum)) {
    throw new Error('GitHub response length is invalid.');
  }
  if (consumer === 'native-buffer') {
    let buffer;
    try {
      buffer = await response.arrayBuffer();
    } catch {
      throw bodyTransportFailure();
    }
    const result = new Uint8Array(buffer);
    if (result.byteLength > maximum) throw new Error('GitHub response is too large.');
    return result;
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      let chunk;
      try {
        chunk = await reader.read();
      } catch {
        throw bodyTransportFailure();
      }
      const { done, value } = chunk;
      if (done) break;
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        throw new Error('GitHub response is too large.');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function readJson(response, maximum = MAX_BYTES, consumer = 'stream') {
  const bytes = await readBytes(response, maximum, consumer);
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error('GitHub response schema is invalid.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('GitHub response schema is invalid.');
  }
  return value;
}

function rateLimited(response) {
  return response.status === 429 || (
    response.status === 403
    && (response.headers.get('x-ratelimit-remaining') === '0' || response.headers.has('retry-after'))
  );
}

function contentTypeIsJson(response) {
  const value = response.headers.get('content-type') || '';
  return /^(?:application\/json|application\/[a-z0-9!#$&^_.+-]+\+json)(?:\s*;|$)/i.test(value);
}

function contentEncoding(response) {
  const value = (response.headers.get('content-encoding') || '').trim().toLowerCase();
  if (!value) return 'none';
  return ['identity', 'gzip', 'br'].includes(value) ? value : 'other';
}

function diagnosticElapsed(startedAt, diagnosticClock) {
  const finishedAt = diagnosticClock();
  const value = Number.isFinite(startedAt) && Number.isFinite(finishedAt)
    ? Math.floor(finishedAt - startedAt)
    : 0;
  return Math.min(60_000, Math.max(0, Number.isSafeInteger(value) ? value : 0));
}

function emitAttemptDiagnostic(observer, diagnosticClock, startedAt, {
  operationKind,
  attempt,
  phase,
  response = null,
  consumer = 'stream',
  outcome,
}) {
  if (typeof observer !== 'function') return;
  try {
    const result = observer(Object.freeze({
      event: 'github-request-attempt',
      operation_kind: ['read', 'token-create'].includes(operationKind) ? operationKind : 'read',
      attempt: Math.min(3, Math.max(1, Number.isSafeInteger(attempt) ? attempt : 1)),
      phase: ['headers', 'body', 'complete'].includes(phase) ? phase : 'headers',
      status: response && Number.isSafeInteger(response.status)
        && response.status >= 100 && response.status <= 599 ? response.status : null,
      content_type_json: response ? contentTypeIsJson(response) : false,
      content_length_present: response ? response.headers.has('content-length') : false,
      content_encoding: response ? contentEncoding(response) : 'none',
      consumer: consumer === 'native-buffer' ? 'native-buffer' : 'stream',
      elapsed_ms: diagnosticElapsed(startedAt, diagnosticClock),
      outcome: ['success', 'transport', 'provider', 'rate-limit'].includes(outcome)
        ? outcome
        : 'provider',
    }));
    if (result && typeof result.then === 'function') {
      void Promise.resolve(result).catch(() => {});
    }
  } catch {
    // Diagnostics are deliberately best-effort and never change request control flow.
  }
}

function retryable(response) {
  return rateLimited(response) || response.status >= 500;
}

function retryDelay(response, attempt, now, random) {
  const retryAfter = response?.headers.get('retry-after');
  if (retryAfter !== null && retryAfter !== undefined) {
    const seconds = Number(retryAfter);
    const value = Number.isFinite(seconds) ? seconds * 1000 : Date.parse(retryAfter) - now;
    if (Number.isFinite(value)) return Math.min(Math.max(0, value), 10_000);
  }
  const reset = Number(response?.headers.get('x-ratelimit-reset'));
  if (Number.isFinite(reset) && reset > 0) {
    return Math.min(Math.max(0, reset * 1000 - now) + Math.floor(random() * 101), 10_000);
  }
  return Math.min(100 * (2 ** (attempt - 1)) + Math.floor(random() * 101), 1_000);
}

async function boundedRequest(fetchImpl, url, init, {
  attempts,
  consume = async (response) => response,
  maximum = MAX_BYTES,
  operationKind = 'read',
  diagnosticObserver = null,
  diagnosticClock = Date.now,
  clock = Date.now,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  random = Math.random,
  timeoutSignal = () => AbortSignal.timeout(10_000),
} = {}) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    let startedAt = null;
    try {
      startedAt = diagnosticClock();
    } catch {
      startedAt = null;
    }
    let response;
    try {
      response = await fetchImpl(url, { ...init, redirect: 'error', signal: timeoutSignal() });
    } catch {
      emitAttemptDiagnostic(diagnosticObserver, diagnosticClock, startedAt, {
        operationKind, attempt, phase: 'headers', outcome: 'transport',
      });
      if (attempt < attempts) {
        await sleep(retryDelay(null, attempt, clock(), random));
        continue;
      }
      throw Object.assign(
        new Error('GitHub transport failed closed.'),
        { failureClass: 'transport' },
      );
    }
    if (response.redirected) {
      emitAttemptDiagnostic(diagnosticObserver, diagnosticClock, startedAt, {
        operationKind, attempt, phase: 'headers', response, outcome: 'provider',
      });
      throw Object.assign(new Error('GitHub redirect was rejected.'), { failureClass: 'provider-evidence' });
    }
    const consumer = responseConsumer(response, attempt, maximum);
    if (!response.ok) {
      const outcome = rateLimited(response) ? 'rate-limit' : 'provider';
      const errorConsumer = responseConsumer(response, attempt, 65_536);
      if (attempt < attempts && retryable(response)) {
        await readBytes(response, 65_536, errorConsumer).catch(() => {});
        emitAttemptDiagnostic(diagnosticObserver, diagnosticClock, startedAt, {
          operationKind, attempt, phase: 'complete', response, consumer: errorConsumer, outcome,
        });
        await sleep(retryDelay(response, attempt, clock(), random));
        continue;
      }
      await readBytes(response, 65_536, errorConsumer).catch(() => {});
      emitAttemptDiagnostic(diagnosticObserver, diagnosticClock, startedAt, {
        operationKind, attempt, phase: 'complete', response, consumer: errorConsumer, outcome,
      });
      throw Object.assign(new Error('GitHub API failed closed.'), {
        status: response.status,
        failureClass: rateLimited(response) ? 'rate-limit' : 'provider-evidence',
      });
    }
    try {
      const value = await consume(response, consumer);
      emitAttemptDiagnostic(diagnosticObserver, diagnosticClock, startedAt, {
        operationKind, attempt, phase: 'complete', response, consumer, outcome: 'success',
      });
      return value;
    } catch (cause) {
      const bodyTransport = cause?.[bodyTransportFailureBrand] === true;
      emitAttemptDiagnostic(diagnosticObserver, diagnosticClock, startedAt, {
        operationKind,
        attempt,
        phase: 'body',
        response,
        consumer,
        outcome: bodyTransport ? 'transport' : 'provider',
      });
      if (!bodyTransport) throw cause;
      if (attempt < attempts) {
        await sleep(retryDelay(null, attempt, clock(), random));
        continue;
      }
      throw Object.assign(
        new Error('GitHub transport failed closed.'),
        { failureClass: 'transport' },
      );
    }
  }
  throw new Error('GitHub API exhausted bounded retries.');
}

function validateReadPayload(kind, value) {
  if (kind === 'commit') {
    if (!/^[a-f0-9]{40}$/.test(String(value.sha ?? ''))) {
      throw new Error('GitHub commit response is invalid.');
    }
    return Object.freeze({ sha: value.sha });
  }
  if (
    !Number.isSafeInteger(value.total_count) || value.total_count < 0
    || !Array.isArray(value.workflow_runs) || value.total_count < value.workflow_runs.length
  ) throw new Error('GitHub workflow-run response is invalid.');
  return Object.freeze({ total_count: value.total_count, workflow_runs: value.workflow_runs });
}

export async function githubApi(fetchImpl, path, token, options = {}) {
  if (options.method && String(options.method).toUpperCase() !== 'GET') {
    throw new Error('GitHub read client only permits GET.');
  }
  if (options.headers || options.body) throw new Error('GitHub read request is immutable.');
  const kind = exactReadPath(path);
  return boundedRequest(fetchImpl, API + path, {
    method: 'GET',
    headers: immutableHeaders(token),
  }, {
    ...options,
    attempts: 3,
    maximum: MAX_BYTES,
    operationKind: 'read',
    consume: async (response, consumer) => validateReadPayload(
      kind,
      await readJson(response, MAX_BYTES, consumer),
    ),
  });
}

function validateInstallationTokenPayload(value, permissionMode) {
  const expiresAt = Math.floor(Date.parse(value.expires_at) / 1000);
  if (
    typeof value.token !== 'string' || value.token.length < 8 || value.token.length > 4096
    || !Number.isSafeInteger(expiresAt)
    || value.repository_selection !== 'selected'
    || !Array.isArray(value.repositories) || value.repositories.length !== 1
    || Number(value.repositories[0]?.id) !== 1183552904
    || value.repositories[0]?.full_name !== 'ScaleSmall/SSAI_Shared'
    || value.permissions?.actions !== permissionMode
    || value.permissions?.contents !== 'read'
    || value.permissions?.metadata !== 'read'
  ) throw new Error('Installation token scope is invalid.');
  return Object.freeze({ token: value.token, expiresAt, permissionMode });
}

export async function createInstallationAccessToken(
  fetchImpl,
  installationId,
  jwt,
  permissionMode,
  options = {},
) {
  const id = String(installationId ?? '');
  if (!/^[1-9][0-9]{0,19}$/.test(id) || !['read', 'write'].includes(permissionMode)) {
    throw new Error('GitHub installation token request is invalid.');
  }
  const permissions = {
    actions: permissionMode,
    contents: 'read',
    metadata: 'read',
  };
  return boundedRequest(fetchImpl, `${API}/app/installations/${id}/access_tokens`, {
    method: 'POST',
    headers: immutableHeaders(jwt, true),
    body: JSON.stringify({ repository_ids: [1183552904], permissions }),
  }, {
    ...options,
    attempts: 3,
    maximum: 262_144,
    operationKind: 'token-create',
    consume: async (response, consumer) => validateInstallationTokenPayload(
      await readJson(response, 262_144, consumer),
      permissionMode,
    ),
  });
}

export function validateDispatchReceipt(value) {
  const id = Number(value?.workflow_run_id);
  if (
    !Number.isSafeInteger(id) || id < 1
    || value.run_url !== `https://api.github.com/repos/ScaleSmall/SSAI_Shared/actions/runs/${id}`
    || value.html_url !== `https://github.com/ScaleSmall/SSAI_Shared/actions/runs/${id}`
  ) throw new Error('Dispatch receipt is invalid.');
  return Object.freeze({ workflow_run_id: id, run_url: value.run_url, html_url: value.html_url });
}

function validateDispatchInputs(inputs) {
  const names = ['envelope_base64url', 'request_id', 'signature_sha256', 'slot_epoch_minute'];
  if (
    !inputs || typeof inputs !== 'object' || Array.isArray(inputs)
    || Object.keys(inputs).sort().join(',') !== names.sort().join(',')
    || !/^[A-Za-z0-9_-]{1,8192}$/.test(String(inputs.envelope_base64url ?? ''))
    || !/^[a-f0-9]{32}$/.test(String(inputs.request_id ?? ''))
    || !/^[a-f0-9]{64}$/.test(String(inputs.signature_sha256 ?? ''))
    || !/^(?:0|[1-9][0-9]{0,11})$/.test(String(inputs.slot_epoch_minute ?? ''))
  ) throw new Error('Dispatch inputs are invalid.');
  return inputs;
}

export async function dispatchWorkflowOnce(fetchImpl, token, inputs, options = {}) {
  validateDispatchInputs(inputs);
  const url = `${API}/repos/ScaleSmall/SSAI_Shared/actions/workflows/344170407/dispatches`;
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'POST',
      redirect: 'error',
      signal: (options.timeoutSignal || (() => AbortSignal.timeout(10_000)))(),
      headers: immutableHeaders(token, true),
      body: JSON.stringify({ ref: 'main', inputs }),
    });
  } catch {
    return Object.freeze({ outcome: 'ambiguous', failure_class: 'transport', status: null });
  }
  if (response.redirected) {
    await readBytes(response, 65_536).catch(() => {});
    return Object.freeze({ outcome: 'ambiguous', failure_class: 'provider-evidence', status: response.status });
  }
  if (response.status !== 200) {
    await readBytes(response, 65_536).catch(() => {});
    return Object.freeze({
      outcome: 'ambiguous',
      failure_class: response.status === 403 || response.status === 429 ? 'rate-limit' : 'provider-evidence',
      status: response.status,
    });
  }
  try {
    const receipt = validateDispatchReceipt(await readJson(response, 262_144));
    return Object.freeze({ outcome: 'confirmed', receipt });
  } catch {
    return Object.freeze({ outcome: 'ambiguous', failure_class: 'provider-evidence', status: 200 });
  }
}
