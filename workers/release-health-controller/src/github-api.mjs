const API = 'https://api.github.com';
const VERSION = '2026-03-10';
const MAX_BYTES = 1_000_000;
export const GITHUB_USER_AGENT = 'ScaleSmall-SSAI-Release-Health-Controller/1.0';
export const WORKFLOW_RUN_PAGE_SIZE = 25;
const workflowIds = new Set(['315630665', '344135917', '344170407']);
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
    Authorization: `Bearer ${token}`,
    'User-Agent': GITHUB_USER_AGENT,
    'X-GitHub-Api-Version': VERSION,
    ...(contentType ? { 'Content-Type': 'application/json' } : {}),
  });
}

async function readBytes(response, maximum = MAX_BYTES) {
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > maximum)) {
    throw new Error('GitHub response length is invalid.');
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
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

async function readJson(response, maximum = MAX_BYTES) {
  const bytes = await readBytes(response, maximum);
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

function retryable(response) {
  return response.status === 429 || response.status >= 500 || (
    response.status === 403
    && (response.headers.get('x-ratelimit-remaining') === '0' || response.headers.has('retry-after'))
  );
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
  clock = Date.now,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  random = Math.random,
  timeoutSignal = () => AbortSignal.timeout(10_000),
} = {}) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    let response;
    try {
      response = await fetchImpl(url, { ...init, redirect: 'error', signal: timeoutSignal() });
    } catch (cause) {
      if (attempt < attempts) {
        await sleep(retryDelay(null, attempt, clock(), random));
        continue;
      }
      throw Object.assign(new Error('GitHub transport failed closed.'), {
        cause,
        failureClass: 'transport',
      });
    }
    if (response.redirected) {
      throw Object.assign(new Error('GitHub redirect was rejected.'), { failureClass: 'provider-evidence' });
    }
    if (!response.ok) {
      if (attempt < attempts && retryable(response)) {
        await readBytes(response, 65_536).catch(() => {});
        await sleep(retryDelay(response, attempt, clock(), random));
        continue;
      }
      await readBytes(response, 65_536).catch(() => {});
      throw Object.assign(new Error('GitHub API failed closed.'), {
        status: response.status,
        requestId: response.headers.get('x-github-request-id') || null,
        failureClass: response.status === 429 || response.status === 403
          ? 'rate-limit'
          : 'provider-evidence',
      });
    }
    return response;
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
  const response = await boundedRequest(fetchImpl, API + path, {
    method: 'GET',
    headers: immutableHeaders(token),
  }, { ...options, attempts: 3 });
  return validateReadPayload(kind, await readJson(response));
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
  const response = await boundedRequest(fetchImpl, `${API}/app/installations/${id}/access_tokens`, {
    method: 'POST',
    headers: immutableHeaders(jwt, true),
    body: JSON.stringify({ repository_ids: [1183552904], permissions }),
  }, { ...options, attempts: 3 });
  const value = await readJson(response, 262_144);
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
