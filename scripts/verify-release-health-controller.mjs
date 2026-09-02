import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import {
  currentLogicalSlot,
  evaluationWindow,
  exactNativeBlocker,
  failureStages,
  sanitizedFailureStage,
  twoConsecutiveCanarySlots,
  outstandingStatuses,
  sanitizedAudit,
} from '../workers/release-health-controller/src/controller.mjs';
import {
  canonicalEnvelope,
  encodeEnvelope,
  parseEnvelope,
  signEnvelope,
  validateEnvelope,
} from '../workers/release-health-controller/src/envelope.mjs';
import {
  createInstallationAccessToken,
  dispatchWorkflowOnce,
  GITHUB_USER_AGENT,
  githubApi,
  validateDispatchReceipt,
  WORKFLOW_RUN_PAGE_SIZE,
} from '../workers/release-health-controller/src/github-api.mjs';
import {
  activationProof,
  chainedAuditHash,
  publicAuditEvent,
  sha256Hex,
} from '../workers/release-health-controller/src/audit.mjs';
import {
  deliverSignedAlert,
  prepareAlert,
  sanitizedAlert,
} from '../workers/release-health-controller/src/alerts.mjs';
import { activationProfileDigest } from '../workers/release-health-controller/src/activation-profile.mjs';
import { ReleaseHealthSlotLedger } from '../workers/release-health-controller/src/store.mjs';
import worker, { ReleaseHealthControllerObject } from '../workers/release-health-controller/src/index.mjs';
import {
  canonicalFallbackEnvelope,
  encodeFallbackEnvelope,
  signFallbackEnvelope,
} from './verify-release-health-fallback-admission.mjs';

const node = (value) => Buffer.from(value);
const minute = (iso) => Math.floor(Date.parse(iso) / 60_000);
const at = (iso) => Date.parse(iso);
const sourceA = 'a'.repeat(64);
const profileA = 'b'.repeat(64);
const sourceB = 'c'.repeat(64);
const profileB = 'd'.repeat(64);
const admissionKey = Buffer.alloc(32, 7).toString('base64');
const alertKey = Buffer.alloc(32, 9).toString('base64');
const mainSha = '1'.repeat(40);
const baseSlot = minute('2026-08-27T20:01:00Z');

function validEnvelope(slot, requestId = '2'.repeat(32), sha = mainSha) {
  const issued = slot * 60 + 600;
  return Object.freeze({
    version: 'ssai-release-health-fallback-v1',
    repository: 'ScaleSmall/SSAI_Shared',
    repository_id: '1183552904',
    workflow_id: '344170407',
    workflow_path: '.github/workflows/release-health-monitor-fallback.yml',
    ref: 'refs/heads/main',
    expected_sha: sha,
    slot_epoch_minute: String(slot),
    request_id: requestId,
    issued_at_epoch_second: String(issued),
    expires_at_epoch_second: String(issued + 300),
  });
}

function runEvidence({
  id,
  workflowId,
  path,
  event = 'schedule',
  createdAt,
  status = 'completed',
  displayTitle = 'synthetic',
  sha = mainSha,
}) {
  return Object.freeze({
    id,
    workflow_id: workflowId,
    path,
    event,
    created_at: createdAt,
    status,
    display_title: displayTitle,
    repository: { id: 1183552904, full_name: 'ScaleSmall/SSAI_Shared' },
    head_branch: 'main',
    head_sha: sha,
    run_attempt: 1,
    url: `https://api.github.com/repos/ScaleSmall/SSAI_Shared/actions/runs/${id}`,
    html_url: `https://github.com/ScaleSmall/SSAI_Shared/actions/runs/${id}`,
  });
}

function payload(runs = []) {
  return { total_count: runs.length, workflow_runs: runs };
}

function trackedJsonResponse(value, {
  status = 200,
  headers = {},
  consumers = [],
  streamFailure = null,
  nativeFailure = null,
  nativeBytes = null,
} = {}) {
  const bytes = new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value));
  const stream = new ReadableStream({
    start(controller) {
      if (streamFailure) controller.error(streamFailure);
      else {
        controller.enqueue(bytes);
        controller.close();
      }
    },
  });
  return {
    status,
    ok: status >= 200 && status < 300,
    redirected: false,
    headers: new Headers({ 'Content-Type': 'application/json; charset=utf-8', ...headers }),
    body: {
      getReader() {
        consumers.push('stream');
        return stream.getReader();
      },
    },
    async arrayBuffer() {
      consumers.push('native-buffer');
      if (nativeFailure) throw nativeFailure;
      const selected = nativeBytes || bytes;
      return selected.buffer.slice(selected.byteOffset, selected.byteOffset + selected.byteLength);
    },
  };
}

function sqliteHarness() {
  const database = new DatabaseSync(':memory:');
  const control = { failAfterCallback: false };
  const sql = {
    exec(statement, ...parameters) {
      if (/^(?:SELECT|PRAGMA)\b/i.test(statement.trim())) {
        return database.prepare(statement).all(...parameters);
      }
      database.prepare(statement).run(...parameters);
      return [];
    },
  };
  const storage = {
    sql,
    transactionSync(callback) {
      database.exec('BEGIN IMMEDIATE');
      try {
        const value = callback();
        if (control.failAfterCallback) {
          control.failAfterCallback = false;
          throw new Error('synthetic transaction failure');
        }
        database.exec('COMMIT');
        return value;
      } catch (error) {
        database.exec('ROLLBACK');
        throw error;
      }
    },
  };
  return { database, control, state: { storage } };
}

function receipt(id) {
  return Object.freeze({
    workflow_run_id: id,
    run_url: `https://api.github.com/repos/ScaleSmall/SSAI_Shared/actions/runs/${id}`,
    html_url: `https://github.com/ScaleSmall/SSAI_Shared/actions/runs/${id}`,
  });
}

async function prepare(store, slot, source, profile, requestByte = '3') {
  const envelope = validEnvelope(slot, requestByte.repeat(32));
  assert.equal(await store.lease(slot, source, profile, slot * 60_000 + 600_000), true);
  assert.equal(await store.prepareDispatch(slot, source, profile, {
    request_id: envelope.request_id,
    expected_sha: envelope.expected_sha,
    expires_at_epoch_second: Number(envelope.expires_at_epoch_second),
    envelope,
  }, slot * 60_000 + 600_000), true);
  return envelope;
}

async function seedActivation(store, firstSlot, source = sourceA, profile = profileA) {
  let result;
  for (const [offset, byte] of [[0, '4'], [15, '5']]) {
    const slot = firstSlot + offset;
    const envelope = await prepare(store, slot, source, profile, byte);
    result = await store.recordObserve(slot, source, profile, {
      decision: 'would_dispatch',
      request_id: envelope.request_id,
      sha: envelope.expected_sha,
    }, slot * 60_000 + 600_000);
  }
  assert.match(result.activation_proof, /^[a-f0-9]{64}$/);
  return result.activation_proof;
}

function apiHarness({ fallbackInventories = [], dispatch = [], alerts = [] } = {}) {
  const calls = [];
  let fallbackIndex = 0;
  let dispatchIndex = 0;
  let alertIndex = 0;
  return {
    calls,
    async fetch(url, options = {}) {
      const method = options.method || 'GET';
      calls.push({ url, method, options });
      if (url === 'https://alerts.scalesmall.ai/release-health-alert') {
        const action = alerts[alertIndex++] ?? new Response('', { status: 202 });
        if (action instanceof Error) throw action;
        return action;
      }
      const parsed = new URL(url);
      if (method === 'GET' && parsed.pathname.endsWith('/runs')) {
        assert.equal(parsed.searchParams.get('per_page'), String(WORKFLOW_RUN_PAGE_SIZE));
        assert.equal(parsed.searchParams.get('branch'), 'main');
      }
      if (method === 'POST' && parsed.pathname.endsWith('/actions/workflows/344170407/dispatches')) {
        const action = dispatch[dispatchIndex++] ?? new Response(JSON.stringify(receipt(9001)), { status: 200 });
        if (action instanceof Error) throw action;
        return action;
      }
      if (parsed.pathname === '/repos/ScaleSmall/SSAI_Shared/commits/main') {
        return new Response(JSON.stringify({ sha: mainSha }), { status: 200 });
      }
      if (parsed.pathname.includes('/actions/workflows/315630665/runs')) {
        return new Response(JSON.stringify(payload()), { status: 200 });
      }
      if (parsed.pathname.includes('/actions/workflows/344135917/runs')) {
        return new Response(JSON.stringify(payload()), { status: 200 });
      }
      if (parsed.pathname.includes('/actions/workflows/344170407/runs')) {
        const action = fallbackInventories[Math.min(fallbackIndex, fallbackInventories.length - 1)] || [];
        fallbackIndex += 1;
        if (action instanceof Error) throw action;
        return new Response(JSON.stringify(payload(action)), { status: 200 });
      }
      throw new Error(`Unexpected synthetic URL: ${url}`);
    },
  };
}

function authHarness(record = []) {
  return async (_fetch, _env, now, permissionMode) => {
    record.push(permissionMode);
    return Object.freeze({
      token: `synthetic-${permissionMode}-credential`,
      expiresAt: now + 3600,
      permissionMode,
    });
  };
}

function boundaryRequest(scheduledTime, nowMs, overrides = {}) {
  return new Request('https://controller.internal/evaluate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scheduledTime, nowMs, ...overrides }),
  });
}

const sourceNames = (await readdir(new URL('../workers/release-health-controller/src/', import.meta.url))).sort();
const sourceHash = createHash('sha256');
for (const name of sourceNames) {
  const source = await readFile(new URL(`../workers/release-health-controller/src/${name}`, import.meta.url), 'utf8');
  assert.doesNotMatch(source, /from ['"](?!\.\/|node:)/);
  sourceHash.update(`${name}\0`).update(source.replace(/\r\n?/g, '\n')).update('\0');
}
const controllerSourceDigest = sourceHash.digest('hex');
const controllerConfig = JSON.parse(await readFile(
  new URL('../workers/release-health-controller/wrangler.jsonc', import.meta.url),
  'utf8',
));
const profileEnvironment = {
  ...controllerConfig.vars,
  CONTROLLER_SOURCE_SHA256: controllerSourceDigest,
};
const controllerProfileDigest = await activationProfileDigest(profileEnvironment);

function controllerEnv(mode, additions = {}) {
  return {
    ...profileEnvironment,
    CONTROLLER_ACTIVATION_PROFILE_SHA256: controllerProfileDigest,
    MODE: mode,
    ADMISSION_HMAC_KEY: admissionKey,
    ALERT_SIGNING_KEY: alertKey,
    FETCH_IMPL: additions.FETCH_IMPL,
    AUTH_PROVIDER: additions.AUTH_PROVIDER,
    RANDOM_UUID: additions.RANDOM_UUID || (() => '66666666-6666-4666-8666-666666666666'),
    TIMEOUT_SIGNAL: additions.TIMEOUT_SIGNAL || (() => new AbortController().signal),
    STRUCTURED_LOG: additions.STRUCTURED_LOG || (() => {}),
    ...additions,
  };
}

// Deterministic scheduling and provider-evidence boundaries.
assert.equal(currentLogicalSlot(at('2026-08-27T20:15:00Z')), baseSlot);
assert.equal(evaluationWindow(at('2026-08-27T20:15:00Z'), baseSlot, at('2026-08-27T20:15:00Z')).eligible, true);
assert.equal(evaluationWindow(at('2026-08-27T20:11:16Z'), baseSlot, at('2026-08-27T20:11:16Z')).eligible, true);
for (const minuteOffset of [10, 11, 12, 13, 14]) {
  const tick = baseSlot * 60_000 + minuteOffset * 60_000;
  assert.equal(evaluationWindow(tick, baseSlot, tick).eligible, true);
  assert.equal(evaluationWindow(tick + 16_000, baseSlot, tick + 16_000).eligible, true);
}
assert.equal(evaluationWindow(baseSlot * 60_000 + 9 * 60_000, baseSlot).eligible, false);
assert.equal(evaluationWindow(baseSlot * 60_000 + 10 * 60_000 - 1, baseSlot).eligible, false);
assert.equal(evaluationWindow(baseSlot * 60_000 + 15 * 60_000, baseSlot).eligible, false);
assert.equal(evaluationWindow(at('2026-08-27T20:16:00Z'), baseSlot, at('2026-08-27T20:15:00Z')).eligible, false);
assert.equal(evaluationWindow(baseSlot * 60_000 + 15 * 60_000, baseSlot, baseSlot * 60_000 + 14 * 60_000 + 16_000).eligible, false);
assert.equal(evaluationWindow(baseSlot * 60_000 + 10 * 60_000 + 16_000, baseSlot, baseSlot * 60_000 + 10 * 60_000 - 1).eligible, false);
const native = runEvidence({
  id: 11,
  workflowId: 315630665,
  path: '.github/workflows/release-health-monitor.yml@refs/heads/main',
  createdAt: '2026-08-27T20:09:00Z',
});
const canaryA = runEvidence({
  id: 12,
  workflowId: 344135917,
  path: '.github/workflows/release-health-monitor-v3.yml@main',
  createdAt: '2026-08-27T19:54:00Z',
});
const canaryB = runEvidence({
  id: 13,
  workflowId: 344135917,
  path: '.github/workflows/release-health-monitor-v3.yml',
  createdAt: '2026-08-27T20:09:00Z',
});
assert.deepEqual(exactNativeBlocker([native], baseSlot), [native]);
assert.equal(twoConsecutiveCanarySlots([canaryA, canaryB], baseSlot), true);
assert.throws(() => exactNativeBlocker([{ ...native, status: 'mystery' }], baseSlot), /malformed/);
assert.throws(() => exactNativeBlocker([{ ...native, url: 'https://example.invalid' }], baseSlot), /malformed/);
assert.deepEqual(outstandingStatuses, ['queued', 'requested', 'waiting', 'pending', 'in_progress']);
assert.throws(() => sanitizedAudit('', { token: 'x' }), /Unsafe/);

// Cross-implementation canonical envelope, strict key decoding, and malformed bounds.
const envelope = validEnvelope(baseSlot);
assert.deepEqual(node(canonicalEnvelope(envelope)), canonicalFallbackEnvelope(envelope));
assert.equal(encodeEnvelope(envelope), encodeFallbackEnvelope(envelope));
assert.deepEqual(parseEnvelope(encodeEnvelope(envelope)), envelope);
assert.equal(await signEnvelope(envelope, admissionKey), signFallbackEnvelope(envelope, admissionKey));
assert.throws(() => validateEnvelope({ ...envelope, extra: 'x' }), /field set/);
assert.throws(() => validateEnvelope({ ...envelope, repository_id: '1' }), /boundary/);
assert.throws(() => validateEnvelope({ ...envelope, issued_at_epoch_second: String(baseSlot * 60 + 599) }), /time relation/);
await assert.rejects(() => signEnvelope(envelope, Buffer.alloc(31).toString('base64')), /HMAC key/);
await assert.rejects(() => signEnvelope(envelope, `${admissionKey}\n`), /HMAC key/);

// Strict GET/token clients, retry classes, streaming limits, and one-attempt dispatch.
assert.equal(GITHUB_USER_AGENT, 'ScaleSmall-SSAI-Release-Health-Controller/1.0');
assert.equal(WORKFLOW_RUN_PAGE_SIZE, 25);
const boundedInventoryPath = '/repos/ScaleSmall/SSAI_Shared/actions/workflows/315630665/runs?event=schedule&branch=main&per_page=25';
assert.deepEqual(await githubApi(
  async (_url, options) => {
    assert.equal(options.headers['User-Agent'], GITHUB_USER_AGENT);
    assert.equal(options.headers['Accept-Encoding'], 'identity');
    return new Response(JSON.stringify(payload()), { status: 200 });
  },
  boundedInventoryPath,
  'synthetic-read-token',
), payload());
await assert.rejects(
  () => githubApi(
    async () => new Response(JSON.stringify(payload()), { status: 200 }),
    boundedInventoryPath.replace('per_page=25', 'per_page=100'),
    'synthetic-read-token',
  ),
  /not allowed/,
);
const oversizedInventoryStream = new ReadableStream({
  start(controller) {
    controller.enqueue(new Uint8Array(600_000));
    controller.enqueue(new Uint8Array(600_000));
    controller.close();
  },
});
await assert.rejects(
  () => githubApi(
    async () => new Response(oversizedInventoryStream, { status: 200 }),
    boundedInventoryPath,
    'synthetic-read-token',
  ),
  /response is too large/,
);
let retryCalls = 0;
const retryDelays = [];
const retryResult = await githubApi(async (_url, options) => {
  retryCalls += 1;
  assert.equal(options.method, 'GET');
  assert.equal(options.redirect, 'manual');
  assert.deepEqual(
    Object.keys(options.headers).sort(),
    ['Accept', 'Accept-Encoding', 'Authorization', 'User-Agent', 'X-GitHub-Api-Version'].sort(),
  );
  assert.equal(options.headers['Accept-Encoding'], 'identity');
  assert.equal(options.headers['User-Agent'], GITHUB_USER_AGENT);
  if (retryCalls === 1) throw new DOMException('synthetic timeout', 'TimeoutError');
  if (retryCalls === 2) return new Response('{}', {
    status: 403,
    headers: { 'Retry-After': 'Thu, 27 Aug 2026 20:00:01 GMT', 'X-RateLimit-Remaining': '0' },
  });
  return new Response(JSON.stringify({ sha: mainSha }), { status: 200 });
}, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
  clock: () => at('2026-08-27T20:00:00Z'),
  sleep: async (delay) => retryDelays.push(delay),
  random: () => 0,
  timeoutSignal: () => new AbortController().signal,
});
assert.deepEqual(retryResult, { sha: mainSha });
assert.equal(retryCalls, 3);
assert.deepEqual(retryDelays, [100, 1000]);
let readRedirectCalls = 0;
await assert.rejects(
  () => githubApi(async (_url, options) => {
    readRedirectCalls += 1;
    assert.equal(options.redirect, 'manual');
    return new Response('', {
      status: 302,
      headers: { Location: 'https://redirect-target.invalid/credential-capture' },
    });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token'),
  (error) => error.failureClass === 'provider-evidence' && error.status === 302,
);
assert.equal(readRedirectCalls, 1);
const bodySensitiveMarker = 'synthetic-sensitive-body-stream-detail';
let bodyRetryCalls = 0;
const bodyAttemptControllers = [];
await assert.rejects(
  () => githubApi(async (_url, options) => {
    bodyRetryCalls += 1;
    const attemptController = bodyAttemptControllers.at(-1);
    assert.equal(options.signal, attemptController.signal);
    return new Response(new ReadableStream({
      start(controller) {
        const fail = () => controller.error(options.signal.reason);
        if (options.signal.aborted) fail();
        else options.signal.addEventListener('abort', fail, { once: true });
      },
    }), { status: 200 });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    sleep: async () => {},
    random: () => 0,
    timeoutSignal: () => {
      const controller = new AbortController();
      bodyAttemptControllers.push(controller);
      queueMicrotask(() => controller.abort(new DOMException(bodySensitiveMarker, 'TimeoutError')));
      return controller.signal;
    },
  }),
  (error) => {
    assert.equal(error.failureClass, 'transport');
    assert.equal(Object.hasOwn(error, 'cause'), false);
    assert.doesNotMatch(error.message, new RegExp(bodySensitiveMarker));
    assert.doesNotMatch(JSON.stringify(error), new RegExp(bodySensitiveMarker));
    return true;
  },
);
assert.equal(bodyRetryCalls, 3);
assert.equal(bodyAttemptControllers.length, 3);
assert.equal(new Set(bodyAttemptControllers.map(({ signal }) => signal)).size, 3);
assert.ok(bodyAttemptControllers.every(({ signal }) => signal.aborted));

const diagnosticKeys = [
  'attempt',
  'consumer',
  'content_encoding',
  'content_length_present',
  'content_type_json',
  'elapsed_ms',
  'event',
  'operation_kind',
  'outcome',
  'phase',
  'status',
].sort();
function assertSingleProviderBodyDiagnostic(events, operationKind) {
  assert.equal(events.length, 1);
  assert.deepEqual(Object.keys(events[0]).sort(), diagnosticKeys);
  assert.deepEqual((({
    attempt, operation_kind: kind, phase, outcome,
  }) => ({ attempt, operation_kind: kind, phase, outcome }))(events[0]), {
    attempt: 1,
    operation_kind: operationKind,
    phase: 'body',
    outcome: 'provider',
  });
  assert.equal(events.some(({ outcome }) => outcome === 'success'), false);
}
const consumerDiagnostics = [];
const consumers = [];
let consumerAttempts = 0;
const consumerResult = await githubApi(async () => {
  consumerAttempts += 1;
  if (consumerAttempts < 3) {
    return trackedJsonResponse({ sha: mainSha }, {
      consumers,
      streamFailure: new DOMException(bodySensitiveMarker, 'AbortError'),
      headers: { 'Content-Length': '50', 'Content-Encoding': consumerAttempts === 1 ? 'gzip' : 'br' },
    });
  }
  const value = JSON.stringify({ sha: mainSha });
  return trackedJsonResponse(value, {
    consumers,
    headers: { 'Content-Length': String(Buffer.byteLength(value)), 'Content-Encoding': 'identity' },
  });
}, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
  diagnosticClock: (() => {
    let now = 0;
    return () => {
      now += 75_000;
      return now;
    };
  })(),
  diagnosticObserver: (event) => consumerDiagnostics.push(event),
  sleep: async () => {},
  random: () => 0,
  timeoutSignal: () => new AbortController().signal,
});
assert.deepEqual(consumerResult, { sha: mainSha });
assert.deepEqual(consumers, ['stream', 'stream', 'native-buffer']);
assert.equal(consumerDiagnostics.length, 3);
assert.deepEqual(consumerDiagnostics.map(({ attempt, consumer, phase, outcome }) => ({
  attempt, consumer, phase, outcome,
})), [
  { attempt: 1, consumer: 'stream', phase: 'body', outcome: 'transport' },
  { attempt: 2, consumer: 'stream', phase: 'body', outcome: 'transport' },
  { attempt: 3, consumer: 'native-buffer', phase: 'complete', outcome: 'success' },
]);
assert.deepEqual(consumerDiagnostics.map(({ content_encoding }) => content_encoding), ['gzip', 'br', 'identity']);
assert.ok(consumerDiagnostics.every((event) => (
  JSON.stringify(Object.keys(event).sort()) === JSON.stringify(diagnosticKeys)
  && event.event === 'github-request-attempt'
  && event.operation_kind === 'read'
  && event.status === 200
  && event.content_type_json === true
  && event.content_length_present === true
  && event.elapsed_ms === 60_000
)));
assert.doesNotMatch(JSON.stringify(consumerDiagnostics), new RegExp(bodySensitiveMarker));

for (const [label, contentLength] of [
  ['absent', null],
  ['noncanonical', '000000000000000000000000000000000000000000000050'],
]) {
  const guardedConsumers = [];
  const guardedDiagnostics = [];
  let guardedAttempt = 0;
  const guardedResult = await githubApi(async () => {
    guardedAttempt += 1;
    const value = JSON.stringify({ sha: mainSha });
    const headers = contentLength === null ? {} : { 'Content-Length': contentLength };
    return trackedJsonResponse(value, guardedAttempt < 3 ? {
      consumers: guardedConsumers,
      streamFailure: new DOMException(`${bodySensitiveMarker}-${label}`, 'AbortError'),
      headers,
    } : { consumers: guardedConsumers, headers });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    diagnosticObserver: (event) => guardedDiagnostics.push(event),
    sleep: async () => {},
    random: () => 0,
    timeoutSignal: () => new AbortController().signal,
  });
  assert.deepEqual(guardedResult, { sha: mainSha }, label);
  assert.deepEqual(guardedConsumers, ['stream', 'stream', 'stream'], label);
  assert.equal(guardedDiagnostics.at(-1).consumer, 'stream', label);
  assert.equal(guardedDiagnostics.at(-1).content_length_present, contentLength !== null, label);
}

const oversizeGuardConsumers = [];
const oversizeGuardDiagnostics = [];
let oversizeGuardAttempt = 0;
await assert.rejects(
  () => githubApi(async () => {
    oversizeGuardAttempt += 1;
    return trackedJsonResponse({ sha: mainSha }, oversizeGuardAttempt < 3 ? {
      consumers: oversizeGuardConsumers,
      streamFailure: new DOMException(bodySensitiveMarker, 'AbortError'),
      headers: { 'Content-Length': '50' },
    } : {
      consumers: oversizeGuardConsumers,
      headers: { 'Content-Length': '1000001' },
    });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    diagnosticObserver: (event) => oversizeGuardDiagnostics.push(event),
    sleep: async () => {},
    random: () => 0,
    timeoutSignal: () => new AbortController().signal,
  }),
  /response length is invalid/,
);
assert.deepEqual(oversizeGuardConsumers, ['stream', 'stream']);
assert.equal(oversizeGuardDiagnostics.at(-1).consumer, 'stream');
assert.equal(oversizeGuardDiagnostics.at(-1).outcome, 'provider');

const errorBodyDiagnostics = [];
let errorBodyAttempt = 0;
await assert.rejects(
  () => githubApi(async () => {
    errorBodyAttempt += 1;
    return trackedJsonResponse('{}', {
      status: 503,
      headers: { 'Content-Length': errorBodyAttempt === 3 ? '70000' : '2' },
    });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    diagnosticObserver: (event) => errorBodyDiagnostics.push(event),
    sleep: async () => {},
    random: () => 0,
    timeoutSignal: () => new AbortController().signal,
  }),
  /API failed closed/,
);
assert.equal(errorBodyDiagnostics.at(-1).attempt, 3);
assert.equal(errorBodyDiagnostics.at(-1).consumer, 'stream');
assert.equal(errorBodyDiagnostics.at(-1).status, 503);

const invalidStatusDiagnostics = [];
await assert.rejects(
  () => githubApi(
    async () => trackedJsonResponse('{}', { status: 99 }),
    '/repos/ScaleSmall/SSAI_Shared/commits/main',
    'synthetic-read-token',
    { diagnosticObserver: (event) => invalidStatusDiagnostics.push(event) },
  ),
  /API failed closed/,
);
assert.equal(invalidStatusDiagnostics.at(-1).status, null);

const providerRedactionDiagnostics = [];
let providerRedactionError;
try {
  await githubApi(
    async () => trackedJsonResponse(bodySensitiveMarker, {
      status: 403,
      headers: {
        'Content-Type': 'text/plain',
        'Content-Encoding': `deflate-${bodySensitiveMarker}`,
        'X-GitHub-Request-Id': bodySensitiveMarker,
      },
    }),
    '/repos/ScaleSmall/SSAI_Shared/commits/main',
    'synthetic-read-token',
    { diagnosticObserver: (event) => providerRedactionDiagnostics.push(event) },
  );
} catch (error) {
  providerRedactionError = error;
}
assert.equal(providerRedactionError?.failureClass, 'provider-evidence');
assert.equal(Object.hasOwn(providerRedactionError, 'requestId'), false);
assert.equal(Object.hasOwn(providerRedactionError, 'cause'), false);
assert.equal(providerRedactionDiagnostics.at(-1).content_type_json, false);
assert.equal(providerRedactionDiagnostics.at(-1).content_encoding, 'other');
assert.deepEqual(Object.keys(providerRedactionDiagnostics.at(-1)).sort(), diagnosticKeys);
assert.doesNotMatch(
  JSON.stringify({ providerRedactionDiagnostics, providerRedactionError }),
  new RegExp(bodySensitiveMarker),
);

const nativeCapConsumers = [];
let nativeCapAttempt = 0;
await assert.rejects(
  () => githubApi(async () => {
    nativeCapAttempt += 1;
    return trackedJsonResponse({ sha: mainSha }, nativeCapAttempt < 3 ? {
      consumers: nativeCapConsumers,
      streamFailure: new DOMException(bodySensitiveMarker, 'AbortError'),
      headers: { 'Content-Length': '50' },
    } : {
      consumers: nativeCapConsumers,
      headers: { 'Content-Length': '2' },
      nativeBytes: new Uint8Array(1_000_001),
    });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    sleep: async () => {},
    random: () => 0,
    timeoutSignal: () => new AbortController().signal,
  }),
  /response is too large/,
);
assert.deepEqual(nativeCapConsumers, ['stream', 'stream', 'native-buffer']);

const nativeFailureConsumers = [];
const nativeFailureDiagnostics = [];
let nativeFailureAttempt = 0;
await assert.rejects(
  () => githubApi(async () => {
    nativeFailureAttempt += 1;
    return trackedJsonResponse({ sha: mainSha }, nativeFailureAttempt < 3 ? {
      consumers: nativeFailureConsumers,
      streamFailure: new DOMException(bodySensitiveMarker, 'AbortError'),
      headers: { 'Content-Length': '50' },
    } : {
      consumers: nativeFailureConsumers,
      nativeFailure: new DOMException(bodySensitiveMarker, 'AbortError'),
      headers: { 'Content-Length': '50' },
    });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    diagnosticObserver: (event) => nativeFailureDiagnostics.push(event),
    sleep: async () => {},
    random: () => 0,
    timeoutSignal: () => new AbortController().signal,
  }),
  (error) => {
    assert.equal(error.failureClass, 'transport');
    assert.equal(Object.hasOwn(error, 'cause'), false);
    return true;
  },
);
assert.deepEqual(nativeFailureConsumers, ['stream', 'stream', 'native-buffer']);
assert.deepEqual(
  (({ attempt, phase, consumer, outcome }) => ({ attempt, phase, consumer, outcome }))(
    nativeFailureDiagnostics.at(-1),
  ),
  { attempt: 3, phase: 'body', consumer: 'native-buffer', outcome: 'transport' },
);
assert.doesNotMatch(JSON.stringify(nativeFailureDiagnostics), new RegExp(bodySensitiveMarker));

const observerFailureResult = await githubApi(
  async () => trackedJsonResponse({ sha: mainSha }),
  '/repos/ScaleSmall/SSAI_Shared/commits/main',
  'synthetic-read-token',
  { diagnosticObserver: () => { throw new Error(bodySensitiveMarker); } },
);
assert.deepEqual(observerFailureResult, { sha: mainSha });
let asyncObserverCalls = 0;
const asyncObserverFailureResult = await githubApi(
  async () => trackedJsonResponse({ sha: mainSha }),
  '/repos/ScaleSmall/SSAI_Shared/commits/main',
  'synthetic-read-token',
  {
    diagnosticObserver: async () => {
      asyncObserverCalls += 1;
      throw new Error(bodySensitiveMarker);
    },
  },
);
await new Promise((resolve) => setImmediate(resolve));
assert.deepEqual(asyncObserverFailureResult, { sha: mainSha });
assert.equal(asyncObserverCalls, 1);
let malformedJsonCalls = 0;
await assert.rejects(
  () => githubApi(async () => {
    malformedJsonCalls += 1;
    return new Response('{', { status: 200 });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    sleep: async () => {},
    timeoutSignal: () => new AbortController().signal,
  }),
  /response schema is invalid/,
);
assert.equal(malformedJsonCalls, 1);
let malformedPayloadCalls = 0;
const malformedCommitDiagnostics = [];
await assert.rejects(
  () => githubApi(async () => {
    malformedPayloadCalls += 1;
    return new Response(JSON.stringify({ sha: 'not-a-commit' }), { status: 200 });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    diagnosticObserver: (event) => malformedCommitDiagnostics.push(event),
    sleep: async () => {},
    timeoutSignal: () => new AbortController().signal,
  }),
  /commit response is invalid/,
);
assert.equal(malformedPayloadCalls, 1);
assertSingleProviderBodyDiagnostic(malformedCommitDiagnostics, 'read');
let malformedWorkflowPayloadCalls = 0;
const malformedWorkflowDiagnostics = [];
await assert.rejects(
  () => githubApi(async () => {
    malformedWorkflowPayloadCalls += 1;
    return new Response(JSON.stringify({ total_count: 0, workflow_runs: [{}] }), { status: 200 });
  }, boundedInventoryPath, 'synthetic-read-token', {
    diagnosticObserver: (event) => malformedWorkflowDiagnostics.push(event),
    sleep: async () => {},
    timeoutSignal: () => new AbortController().signal,
  }),
  /workflow-run response is invalid/,
);
assert.equal(malformedWorkflowPayloadCalls, 1);
assertSingleProviderBodyDiagnostic(malformedWorkflowDiagnostics, 'read');
let nonRetryableHttpCalls = 0;
await assert.rejects(
  () => githubApi(async () => {
    nonRetryableHttpCalls += 1;
    return new Response('{}', { status: 404 });
  }, '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-read-token', {
    sleep: async () => {},
    timeoutSignal: () => new AbortController().signal,
  }),
  /API failed closed/,
);
assert.equal(nonRetryableHttpCalls, 1);
await assert.rejects(
  () => githubApi(async () => new Response('{}'), '/repos/ScaleSmall/SSAI_Shared/unknown', 'synthetic-token'),
  /not allowed/,
);
await assert.rejects(
  () => githubApi(async () => new Response('{}'), '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-token', { headers: {} }),
  /immutable/,
);
await assert.rejects(
  () => githubApi(async () => new Response('{}', { headers: { 'Content-Length': '-1' } }), '/repos/ScaleSmall/SSAI_Shared/commits/main', 'synthetic-token'),
  /length is invalid/,
);
let tokenCalls = 0;
const tokenDiagnostics = [];
const tokenValue = await createInstallationAccessToken(async (_url, options) => {
  tokenCalls += 1;
  assert.equal(options.headers['User-Agent'], GITHUB_USER_AGENT);
  assert.equal(options.headers['Accept-Encoding'], 'identity');
  assert.equal(options.redirect, 'manual');
  const body = JSON.parse(options.body);
  assert.deepEqual(body, {
    repository_ids: [1183552904],
    permissions: { actions: 'read', contents: 'read', metadata: 'read' },
  });
  if (tokenCalls === 1) return new Response('{}', { status: 503 });
  return new Response(JSON.stringify({
    token: 'synthetic-installation-token',
    expires_at: '2026-08-27T21:00:00Z',
    repository_selection: 'selected',
    repositories: [{ id: 1183552904, full_name: 'ScaleSmall/SSAI_Shared' }],
    permissions: { actions: 'read', contents: 'read', metadata: 'read' },
  }), { status: 201 });
}, '12345', 'synthetic-app-jwt', 'read', {
  diagnosticObserver: (event) => tokenDiagnostics.push(event),
  sleep: async () => {},
  timeoutSignal: () => new AbortController().signal,
});
assert.equal(tokenCalls, 2);
assert.equal(tokenValue.permissionMode, 'read');
assert.deepEqual(tokenDiagnostics.map(({ attempt, operation_kind, outcome }) => ({
  attempt, operation_kind, outcome,
})), [
  { attempt: 1, operation_kind: 'token-create', outcome: 'provider' },
  { attempt: 2, operation_kind: 'token-create', outcome: 'success' },
]);
assert.ok(tokenDiagnostics.every((event) => (
  JSON.stringify(Object.keys(event).sort()) === JSON.stringify(diagnosticKeys)
)));
let tokenRedirectCalls = 0;
await assert.rejects(
  () => createInstallationAccessToken(async (_url, options) => {
    tokenRedirectCalls += 1;
    assert.equal(options.redirect, 'manual');
    return new Response('', {
      status: 307,
      headers: { Location: 'https://redirect-target.invalid/credential-capture' },
    });
  }, '12345', 'synthetic-app-jwt', 'read'),
  (error) => error.failureClass === 'provider-evidence' && error.status === 307,
);
assert.equal(tokenRedirectCalls, 1);
let tokenBodyRetryCalls = 0;
let tokenBodySignalCalls = 0;
const tokenAfterBodyRetry = await createInstallationAccessToken(async (_url, options) => {
  tokenBodyRetryCalls += 1;
  assert.deepEqual(JSON.parse(options.body), {
    repository_ids: [1183552904],
    permissions: { actions: 'read', contents: 'read', metadata: 'read' },
  });
  if (tokenBodyRetryCalls < 3) {
    return new Response(new ReadableStream({
      pull() {
        throw new DOMException(bodySensitiveMarker, 'AbortError');
      },
    }), { status: 201 });
  }
  return new Response(JSON.stringify({
    token: 'synthetic-token-after-body-retry',
    expires_at: '2026-08-27T21:00:00Z',
    repository_selection: 'selected',
    repositories: [{ id: 1183552904, full_name: 'ScaleSmall/SSAI_Shared' }],
    permissions: { actions: 'read', contents: 'read', metadata: 'read' },
  }), { status: 201 });
}, '12345', 'synthetic-app-jwt', 'read', {
  sleep: async () => {},
  random: () => 0,
  timeoutSignal: () => {
    tokenBodySignalCalls += 1;
    return new AbortController().signal;
  },
});
assert.equal(tokenBodyRetryCalls, 3);
assert.equal(tokenBodySignalCalls, 3);
assert.equal(tokenAfterBodyRetry.permissionMode, 'read');
assert.equal(tokenAfterBodyRetry.token, 'synthetic-token-after-body-retry');
let invalidScopeCalls = 0;
const invalidScopeDiagnostics = [];
await assert.rejects(
  () => createInstallationAccessToken(async () => {
    invalidScopeCalls += 1;
    return new Response(JSON.stringify({
      token: 'synthetic-overprivileged-token',
      expires_at: '2026-08-27T21:00:00Z',
      repository_selection: 'selected',
      repositories: [{ id: 1183552904, full_name: 'ScaleSmall/SSAI_Shared' }],
      permissions: { actions: 'write', contents: 'read', metadata: 'read' },
    }), { status: 201 });
  }, '12345', 'synthetic-app-jwt', 'read', {
    diagnosticObserver: (event) => invalidScopeDiagnostics.push(event),
    sleep: async () => {},
    timeoutSignal: () => new AbortController().signal,
  }),
  /scope is invalid/,
);
assert.equal(invalidScopeCalls, 1);
assertSingleProviderBodyDiagnostic(invalidScopeDiagnostics, 'token-create');
let writeTokenCalls = 0;
const writeTokenValue = await createInstallationAccessToken(async (_url, options) => {
  writeTokenCalls += 1;
  assert.equal(options.headers['User-Agent'], GITHUB_USER_AGENT);
  assert.deepEqual(JSON.parse(options.body), {
    repository_ids: [1183552904],
    permissions: { actions: 'write', contents: 'read', metadata: 'read' },
  });
  return new Response(JSON.stringify({
    token: 'synthetic-write-installation-token',
    expires_at: '2026-08-27T21:00:00Z',
    repository_selection: 'selected',
    repositories: [{ id: 1183552904, full_name: 'ScaleSmall/SSAI_Shared' }],
    permissions: { actions: 'write', contents: 'read', metadata: 'read' },
  }), { status: 201 });
}, '12345', 'synthetic-app-jwt', 'write', {
  sleep: async () => {},
  timeoutSignal: () => new AbortController().signal,
});
assert.equal(writeTokenCalls, 1);
assert.equal(writeTokenValue.permissionMode, 'write');
assert.throws(() => validateDispatchReceipt({ workflow_run_id: 1, run_url: 'bad', html_url: 'bad' }), /invalid/);
const dispatchInputs = {
  envelope_base64url: encodeEnvelope(envelope),
  slot_epoch_minute: envelope.slot_epoch_minute,
  request_id: envelope.request_id,
  signature_sha256: await signEnvelope(envelope, admissionKey),
};
let dispatchCalls = 0;
const ambiguous = await dispatchWorkflowOnce(async (_url, options) => {
  dispatchCalls += 1;
  assert.equal(options.method, 'POST');
  assert.equal(options.redirect, 'manual');
  assert.equal(options.headers['User-Agent'], GITHUB_USER_AGENT);
  assert.equal(options.headers['Accept-Encoding'], 'identity');
  throw new DOMException('synthetic timeout', 'TimeoutError');
}, 'synthetic-write-token', dispatchInputs, { timeoutSignal: () => new AbortController().signal });
assert.equal(dispatchCalls, 1);
assert.equal(ambiguous.outcome, 'ambiguous');
assert.equal(ambiguous.failure_class, 'transport');
let dispatchRedirectCalls = 0;
const redirectDispatch = await dispatchWorkflowOnce(async (_url, options) => {
  dispatchRedirectCalls += 1;
  assert.equal(options.redirect, 'manual');
  return new Response('', {
    status: 303,
    headers: { Location: 'https://redirect-target.invalid/credential-capture' },
  });
}, 'synthetic-write-token', dispatchInputs);
assert.deepEqual(redirectDispatch, {
  outcome: 'ambiguous', failure_class: 'provider-evidence', status: 303,
});
assert.equal(dispatchRedirectCalls, 1);
let malformedCalls = 0;
const malformed = await dispatchWorkflowOnce(async () => {
  malformedCalls += 1;
  return new Response('{}', { status: 200 });
}, 'synthetic-write-token', dispatchInputs);
assert.equal(malformedCalls, 1);
assert.equal(malformed.outcome, 'ambiguous');
let non200Calls = 0;
const non200 = await dispatchWorkflowOnce(async () => {
  non200Calls += 1;
  return new Response('{"message":"synthetic unavailable"}', { status: 503 });
}, 'synthetic-write-token', dispatchInputs);
assert.equal(non200Calls, 1);
assert.deepEqual(non200, { outcome: 'ambiguous', failure_class: 'provider-evidence', status: 503 });
let oversizedCalls = 0;
const oversized = await dispatchWorkflowOnce(async () => {
  oversizedCalls += 1;
  return new Response('{}', { status: 200, headers: { 'Content-Length': '262145' } });
}, 'synthetic-write-token', dispatchInputs);
assert.equal(oversizedCalls, 1);
assert.deepEqual(oversized, { outcome: 'ambiguous', failure_class: 'provider-evidence', status: 200 });
let redirectCalls = 0;
const redirectResponse = new Response('', { status: 302, headers: { Location: 'https://example.invalid/' } });
Object.defineProperty(redirectResponse, 'redirected', { value: true });
const redirected = await dispatchWorkflowOnce(async () => {
  redirectCalls += 1;
  return redirectResponse;
}, 'synthetic-write-token', dispatchInputs);
assert.equal(redirectCalls, 1);
assert.deepEqual(redirected, { outcome: 'ambiguous', failure_class: 'provider-evidence', status: 302 });

// Actual SQLite store: activation, rollback, digest invalidation, standby, circuit, and outbox.
const storeHarness = sqliteHarness();
let store = new ReleaseHealthSlotLedger(storeHarness.state, { MODE: 'observe' });
assert.deepEqual(
  await Promise.all([
    store.lease(baseSlot, sourceA, profileA, at('2026-08-27T20:11:00Z')),
    store.lease(baseSlot, sourceA, profileA, at('2026-08-27T20:11:00Z')),
  ]),
  [true, false],
);
const firstEnvelope = validEnvelope(baseSlot, '7'.repeat(32));
assert.equal(await store.prepareDispatch(baseSlot, sourceA, profileA, {
  request_id: firstEnvelope.request_id,
  expected_sha: firstEnvelope.expected_sha,
  expires_at_epoch_second: Number(firstEnvelope.expires_at_epoch_second),
  envelope: firstEnvelope,
}, at('2026-08-27T20:11:00Z')), true);
const columns = storeHarness.database.prepare('PRAGMA table_info(slots)').all().map((column) => column.name);
assert.equal(columns.includes('inputs_json'), false);
assert.equal(columns.some((name) => /signature/i.test(name)), false);
assert.doesNotMatch(JSON.stringify(storeHarness.database.prepare('SELECT * FROM slots').all()), /signature_sha256/);
const beforeRollbackAudit = storeHarness.database.prepare('SELECT COUNT(*) AS count FROM audit').get().count;
storeHarness.control.failAfterCallback = true;
await assert.rejects(
  () => store.recordObserve(baseSlot, sourceA, profileA, {
    decision: 'would_dispatch', request_id: firstEnvelope.request_id, sha: mainSha,
  }, at('2026-08-27T20:11:00Z')),
  /synthetic transaction failure/,
);
assert.equal((await store.getSlot(baseSlot, sourceA, profileA)).phase, 'prepared');
assert.equal(storeHarness.database.prepare('SELECT COUNT(*) AS count FROM audit').get().count, beforeRollbackAudit);
const firstObserve = await store.recordObserve(baseSlot, sourceA, profileA, {
  decision: 'would_dispatch', request_id: firstEnvelope.request_id, sha: mainSha,
}, at('2026-08-27T20:11:00Z'));
assert.equal(firstObserve.activation_proof, null);
const secondEnvelope = await prepare(store, baseSlot + 15, sourceA, profileA, '8');
const secondObserve = await store.recordObserve(baseSlot + 15, sourceA, profileA, {
  decision: 'would_dispatch', request_id: secondEnvelope.request_id, sha: mainSha,
}, (baseSlot + 15) * 60_000 + 600_000);
assert.match(secondObserve.activation_proof, /^[a-f0-9]{64}$/);
store = new ReleaseHealthSlotLedger(storeHarness.state, { MODE: 'active' });
assert.equal(await store.activationReady(sourceA, profileA, secondObserve.activation_proof), true);
assert.equal(await store.activationReady(sourceA, profileB, secondObserve.activation_proof), false);
await prepare(store, baseSlot + 30, sourceB, profileB, '9');
assert.equal(await store.activationReady(sourceB, profileB, secondObserve.activation_proof), false);

const abandonedHarness = sqliteHarness();
const abandonedStore = new ReleaseHealthSlotLedger(abandonedHarness.state, { MODE: 'active' });
const abandonedEnvelope = await prepare(abandonedStore, baseSlot, sourceA, profileA, 'a');
const abandonedAlert = await prepareAlert({
  slot: baseSlot,
  failure_class: 'configuration',
  status: null,
  phase: 'terminal',
  decision: 'prepared-abandoned',
});
const auditBeforeAbandonment = abandonedHarness.database.prepare('SELECT COUNT(*) AS count FROM audit').get().count;
abandonedHarness.control.failAfterCallback = true;
await assert.rejects(
  () => abandonedStore.abandonUnattempted(
    baseSlot,
    'prepared',
    baseSlot * 60_000 + 600_000,
    'configuration',
    abandonedAlert,
  ),
  /synthetic transaction failure/,
);
assert.equal((await abandonedStore.getSlot(baseSlot, sourceA, profileA)).phase, 'prepared');
assert.equal(abandonedHarness.database.prepare('SELECT COUNT(*) AS count FROM alert_outbox').get().count, 0);
assert.equal(abandonedHarness.database.prepare('SELECT COUNT(*) AS count FROM audit').get().count, auditBeforeAbandonment);
const abandoned = await abandonedStore.abandonUnattempted(
  baseSlot,
  'prepared',
  baseSlot * 60_000 + 600_000,
  'configuration',
  abandonedAlert,
);
assert.equal(abandoned.decision, 'prepared-abandoned');
assert.equal(abandoned.request_id, abandonedEnvelope.request_id);
assert.equal((await abandonedStore.getSlot(baseSlot, sourceA, profileA)).phase, 'terminal');
assert.equal((await abandonedStore.getSlot(baseSlot, sourceB, profileB)).decision, 'digest-mismatch');
assert.equal(await abandonedStore.lease(
  baseSlot,
  sourceB,
  profileB,
  baseSlot * 60_000 + 600_000,
), false);
const abandonedOutbox = abandonedHarness.database.prepare('SELECT * FROM alert_outbox').get();
assert.equal(abandonedOutbox.alert_id, abandonedAlert.alert_id);
assert.equal(abandonedOutbox.source_digest, sourceA);
assert.equal(abandonedOutbox.profile_digest, profileA);
assert.equal(abandonedOutbox.state, 'pending');

const staleHarness = sqliteHarness();
const staleStore = new ReleaseHealthSlotLedger(staleHarness.state, { MODE: 'observe' });
assert.equal(await staleStore.lease(
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
  baseSlot * 60_000 + 600_000,
), true);
await prepare(staleStore, baseSlot + 15, controllerSourceDigest, controllerProfileDigest, 'd');
const staleApi = apiHarness();
const staleObject = new ReleaseHealthControllerObject(staleHarness.state, controllerEnv('observe', {
  FETCH_IMPL: staleApi.fetch,
  AUTH_PROVIDER: authHarness([]),
}));
const staleBoundary = await staleObject.fetch(boundaryRequest(
  (baseSlot + 30) * 60_000,
  (baseSlot + 30) * 60_000,
));
assert.equal(staleBoundary.status, 200);
assert.equal((await staleBoundary.json()).decision, 'prepared-abandoned');
assert.equal((await staleStore.getSlot(
  baseSlot, controllerSourceDigest, controllerProfileDigest,
)).result.decision, 'lease-abandoned');
assert.equal((await staleStore.getSlot(
  baseSlot + 15, controllerSourceDigest, controllerProfileDigest,
)).result.decision, 'prepared-abandoned');
assert.equal(staleHarness.database.prepare('SELECT COUNT(*) AS count FROM alert_outbox').get().count, 2);
assert.equal(staleApi.calls.length, 0);
const auditBeforeStandby = storeHarness.database.prepare('SELECT COUNT(*) AS count FROM audit').get().count;
assert.equal((await store.updateStandby(sourceA, profileA, true, baseSlot + 30, Date.now())).outcome, 'standby-entered');
assert.equal((await store.updateStandby(sourceA, profileA, true, baseSlot + 45, Date.now())).changed, true);
assert.equal((await store.updateStandby(sourceA, profileA, false, baseSlot + 45, Date.now())).outcome, 'standby-resumed');
assert.equal(storeHarness.database.prepare('SELECT COUNT(*) AS count FROM audit').get().count, auditBeforeStandby + 3);

const circuitHarness = sqliteHarness();
const circuitStore = new ReleaseHealthSlotLedger(circuitHarness.state, { MODE: 'active' });
const circuitProof = await seedActivation(circuitStore, baseSlot, sourceA, profileA);
for (let index = 0; index < 4; index += 1) {
  const slot = baseSlot + 30 + index * 15;
  const preparedEnvelope = await prepare(circuitStore, slot, sourceA, profileA, String(index + 1));
  const permit = await circuitStore.consumePostPermit(
    slot, sourceA, profileA, circuitProof, slot * 60 + 600, slot * 60_000 + 600_000,
  );
  assert.equal(permit.permit, true);
  const unknown = await prepareAlert({
    slot,
    failure_class: 'dispatch-unknown',
    status: null,
    phase: 'unknown',
    decision: 'dispatch-unknown',
    request_id: preparedEnvelope.request_id,
  });
  const open = await prepareAlert({
    slot,
    failure_class: 'circuit-open',
    status: null,
    phase: 'unknown',
    decision: 'circuit-open',
    request_id: preparedEnvelope.request_id,
  });
  const outcome = await circuitStore.markUnknown(
    slot, sourceA, profileA, { failure_class: 'transport', status: null },
    slot * 60_000 + 600_000, unknown, open,
  );
  assert.equal(outcome.circuit, index === 3 ? 'opened' : 'closed');
}
let generation = circuitHarness.database.prepare(
  'SELECT * FROM generations WHERE source_digest=? AND profile_digest=?',
).get(sourceA, profileA);
assert.equal(generation.circuit_state, 'open');
assert.equal(generation.circuit_open_until_slot, baseSlot + 30 + 45 + 60);
assert.equal(circuitHarness.database.prepare('SELECT COUNT(*) AS count FROM alert_outbox').get().count, 5);
const blockedSlot = baseSlot + 90;
await prepare(circuitStore, blockedSlot, sourceA, profileA, 'a');
assert.equal((await circuitStore.consumePostPermit(
  blockedSlot, sourceA, profileA, circuitProof, blockedSlot * 60 + 600, blockedSlot * 60_000 + 600_000,
)).outcome, 'circuit-open');
const probeSlot = baseSlot + 135;
const probeEnvelope = await prepare(circuitStore, probeSlot, sourceA, profileA, 'b');
const probe = await circuitStore.consumePostPermit(
  probeSlot, sourceA, profileA, circuitProof, probeSlot * 60 + 600, probeSlot * 60_000 + 600_000,
);
assert.equal(probe.outcome, 'circuit-half-open');
const probeUnknown = await prepareAlert({
  slot: probeSlot,
  failure_class: 'dispatch-unknown',
  status: null,
  phase: 'unknown',
  decision: 'dispatch-unknown',
  request_id: probeEnvelope.request_id,
});
const probeOpen = await prepareAlert({
  slot: probeSlot,
  failure_class: 'circuit-open',
  status: null,
  phase: 'unknown',
  decision: 'circuit-open',
  request_id: probeEnvelope.request_id,
});
assert.equal((await circuitStore.markUnknown(
  probeSlot,
  sourceA,
  profileA,
  { failure_class: 'transport', status: null },
  probeSlot * 60_000 + 600_000,
  probeUnknown,
  probeOpen,
)).circuit, 'opened');
generation = circuitHarness.database.prepare(
  'SELECT * FROM generations WHERE source_digest=? AND profile_digest=?',
).get(sourceA, profileA);
assert.equal(generation.circuit_state, 'open');
assert.equal(generation.circuit_open_until_slot, probeSlot + 60);
assert.equal(generation.circuit_episode, 2);
const recoveryProbeSlot = probeSlot + 60;
await prepare(circuitStore, recoveryProbeSlot, sourceA, profileA, 'c');
assert.equal((await circuitStore.consumePostPermit(
  recoveryProbeSlot,
  sourceA,
  profileA,
  circuitProof,
  recoveryProbeSlot * 60 + 600,
  recoveryProbeSlot * 60_000 + 600_000,
)).outcome, 'circuit-half-open');
await circuitStore.confirmDispatch(
  recoveryProbeSlot,
  sourceA,
  profileA,
  receipt(9200),
  'dispatched',
  recoveryProbeSlot * 60_000 + 600_000,
);
await circuitStore.terminalizeConfirmed(
  recoveryProbeSlot,
  sourceA,
  profileA,
  'dispatched',
  recoveryProbeSlot * 60_000 + 600_000,
);
generation = circuitHarness.database.prepare(
  'SELECT * FROM generations WHERE source_digest=? AND profile_digest=?',
).get(sourceA, profileA);
assert.equal(generation.circuit_state, 'closed');
const chain = circuitHarness.database.prepare('SELECT previous_hash,event_hash,event_json,result_digest FROM audit ORDER BY sequence').all();
for (let index = 0; index < chain.length; index += 1) {
  assert.equal(chain[index].previous_hash, index === 0 ? '0'.repeat(64) : chain[index - 1].event_hash);
  assert.equal(JSON.parse(chain[index].event_json).result_digest, chain[index].result_digest);
}

const claimed = await circuitStore.claimAlerts(recoveryProbeSlot * 60_000 + 600_000, 1);
assert.equal(claimed.length, 1);
const alertAttempts = [];
await assert.rejects(() => deliverSignedAlert(claimed[0], {
  sink: 'https://alerts.scalesmall.ai/release-health-alert',
  keyBase64: alertKey,
  fetchImpl: async (_url, options) => {
    alertAttempts.push(options.headers);
    throw new DOMException('synthetic alert timeout', 'TimeoutError');
  },
  timeoutSignal: () => new AbortController().signal,
}), /timeout/);
let alertRedirectCalls = 0;
await assert.rejects(() => deliverSignedAlert(claimed[0], {
  sink: 'https://alerts.scalesmall.ai/release-health-alert',
  keyBase64: alertKey,
  fetchImpl: async (_url, options) => {
    alertRedirectCalls += 1;
    assert.equal(options.redirect, 'manual');
    return new Response('', {
      status: 308,
      headers: { Location: 'https://redirect-target.invalid/credential-capture' },
    });
  },
  timeoutSignal: () => new AbortController().signal,
}), (error) => error.message === 'Alert delivery failed.' && error.status === 308);
assert.equal(alertRedirectCalls, 1);
await circuitStore.rejectAlert(claimed[0].alert_id, null, 'transport', recoveryProbeSlot * 60_000 + 600_000);
const reclaimed = await circuitStore.claimAlerts(recoveryProbeSlot * 60_000 + 661_000, 1);
assert.equal(reclaimed[0].alert_id, claimed[0].alert_id);
await deliverSignedAlert(reclaimed[0], {
  sink: 'https://alerts.scalesmall.ai/release-health-alert',
  keyBase64: alertKey,
  fetchImpl: async (_url, options) => {
    alertAttempts.push(options.headers);
    return new Response('', { status: 202 });
  },
  timeoutSignal: () => new AbortController().signal,
});
assert.equal(alertAttempts[0]['X-SSAI-Alert-Id'], alertAttempts[1]['X-SSAI-Alert-Id']);
assert.equal(alertAttempts[0]['X-SSAI-Alert-Signature'], alertAttempts[1]['X-SSAI-Alert-Signature']);
assert.equal(circuitHarness.database.prepare('PRAGMA table_info(alert_outbox)').all().some((column) => /signature/i.test(column.name)), false);

// Public /healthz and internal Durable Object /evaluate boundaries.
assert.equal(typeof worker.fetch, 'function');
let healthClock = at('2026-08-27T20:02:16Z');
const healthHarness = sqliteHarness();
const healthLogs = [];
const healthEnv = controllerEnv('observe', {
  CLOCK_NOW: () => healthClock,
  STRUCTURED_LOG: (line) => healthLogs.push(JSON.parse(line)),
});
const healthObject = new ReleaseHealthControllerObject(healthHarness.state, healthEnv);
healthEnv.SLOT_LEDGER = {
  idFromName(name) {
    assert.equal(name, 'ssai-release-health-controller-v2');
    return 'singleton';
  },
  get(id) {
    assert.equal(id, 'singleton');
    return {
      fetch: (input, init) => healthObject.fetch(
        input instanceof Request ? input : new Request(input, init),
      ),
    };
  },
};
const publicHealthRequest = () => new Request(
  'https://release-health-controller.scalesmall.ai/healthz',
);
const virginHealth = await worker.fetch(publicHealthRequest(), healthEnv);
assert.equal(virginHealth.status, 503);
const virginHealthBody = await virginHealth.json();
assert.equal(virginHealthBody.status, 'unhealthy');
assert.equal(virginHealthBody.last_completed_tick, null);
assert.equal(virginHealthBody.last_scheduled_time, null);
assert.equal(virginHealthBody.last_decision, null);
assert.deepEqual(virginHealthBody.checks, {
  fresh: false,
  no_dead_alerts: true,
  no_terminal_failure: true,
  no_internal_failure: true,
});
assert.equal((await worker.fetch(new Request(
  'https://release-health-controller.scalesmall.ai/healthz?verbose=true',
), healthEnv)).status, 404);
assert.equal((await worker.fetch(new Request(
  'https://release-health-controller.scalesmall.ai/healthz', { method: 'POST' },
), healthEnv)).status, 405);
assert.equal((await worker.fetch(new Request(
  'https://other.example/healthz',
), healthEnv)).status, 404);
const completedTick = await healthObject.fetch(boundaryRequest(healthClock, healthClock));
assert.equal(completedTick.status, 200);
assert.equal((await completedTick.json()).decision, 'outside-window');
let publicHealth = await worker.fetch(publicHealthRequest(), healthEnv);
let publicHealthBody = await publicHealth.json();
assert.equal(publicHealth.status, 200, JSON.stringify(publicHealthBody));
assert.equal(publicHealthBody.status, 'healthy');
assert.equal(publicHealthBody.mode, 'observe');
assert.equal(publicHealthBody.last_completed_tick, new Date(healthClock).toISOString());
assert.equal(publicHealthBody.last_scheduled_time, '2026-08-27T20:02:16.000Z');
assert.equal(publicHealthBody.last_decision, 'outside-window');
assert.equal(publicHealthBody.source_digest, controllerSourceDigest);
assert.equal(publicHealthBody.profile_digest, controllerProfileDigest);
assert.equal(publicHealthBody.config_digest, null);
assert.deepEqual(publicHealthBody.alerts, { pending: 0, dead: 0 });
assert.deepEqual(publicHealthBody.checks, {
  fresh: true,
  no_dead_alerts: true,
  no_terminal_failure: true,
  no_internal_failure: true,
});
assert.doesNotMatch(JSON.stringify(publicHealthBody), /credential|hmac|private|signature|token/i);
healthClock += 301_000;
publicHealth = await worker.fetch(publicHealthRequest(), healthEnv);
publicHealthBody = await publicHealth.json();
assert.equal(publicHealth.status, 503);
assert.equal(publicHealthBody.checks.fresh, false);

const unhealthyHarness = sqliteHarness();
const unhealthyEnv = controllerEnv('invalid', { CLOCK_NOW: () => healthClock });
const unhealthyObject = new ReleaseHealthControllerObject(unhealthyHarness.state, unhealthyEnv);
const failedTick = await unhealthyObject.fetch(boundaryRequest(healthClock, healthClock));
assert.equal(failedTick.status, 503);
const failedTickResult = await failedTick.json();
assert.equal(failedTickResult.failure_class, 'internal');
assert.equal(failedTickResult.failure_stage, 'runtime-boundary');
const unhealthy = await unhealthyObject.fetch(new Request('https://controller.internal/healthz'));
assert.equal(unhealthy.status, 503);
const unhealthyBody = await unhealthy.json();
assert.equal(unhealthyBody.checks.no_terminal_failure, false);
assert.equal(unhealthyBody.checks.no_internal_failure, false);

for (const failureClass of [
  'provider-evidence',
  'transport',
  'rate-limit',
  'dispatch-unknown',
  'circuit-open',
  'configuration',
  'prepared-expired',
]) {
  const failureHarness = sqliteHarness();
  const failureStore = new ReleaseHealthSlotLedger(failureHarness.state, healthEnv);
  await failureStore.recordCompletedTick({
    scheduledTime: healthClock,
    completedAt: healthClock,
    sourceDigest: controllerSourceDigest,
    profileDigest: controllerProfileDigest,
    decision: 'failed-closed',
    failureClass,
  });
  const status = await failureStore.healthStatus(
    healthClock,
    controllerSourceDigest,
    controllerProfileDigest,
    300_000,
  );
  assert.equal(status.healthy, false, failureClass);
  assert.equal(status.terminal_failure, true, failureClass);
}

// An exhausted, pre-dispatch transient failure keeps one lease retryable until the final minute.
const transientLeaseHarness = sqliteHarness();
const transientLeaseApi = apiHarness();
const transientLeaseMarker = 'synthetic-sensitive-transient-lease-detail';
let transientAuthCalls = 0;
let transientDispatchPosts = 0;
const transientLeaseEnv = controllerEnv('observe', {
  AUTH_PROVIDER: async (_fetch, _env, now, permissionMode) => {
    transientAuthCalls += 1;
    if (transientAuthCalls === 1) {
      throw Object.assign(new Error(transientLeaseMarker), { failureClass: 'transport' });
    }
    return Object.freeze({
      token: `synthetic-${permissionMode}-credential`,
      expiresAt: now + 3600,
      permissionMode,
    });
  },
  FETCH_IMPL: async (url, options) => {
    if (String(url).includes('/actions/workflows/344170407/dispatches')) transientDispatchPosts += 1;
    return transientLeaseApi.fetch(url, options);
  },
});
const transientLeaseObject = new ReleaseHealthControllerObject(transientLeaseHarness.state, transientLeaseEnv);
const transientFirstTime = baseSlot * 60_000 + 10 * 60_000 + 16_000;
const transientFirstResponse = await transientLeaseObject.fetch(
  boundaryRequest(transientFirstTime, transientFirstTime),
);
const transientFirstResult = await transientFirstResponse.json();
assert.deepEqual(transientFirstResult, {
  decision: 'failed-closed',
  failure_class: 'transport',
  failure_stage: 'read-auth',
});
const transientLeaseStore = new ReleaseHealthSlotLedger(transientLeaseHarness.state, transientLeaseEnv);
assert.equal((await transientLeaseStore.getSlot(
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
)).phase, 'leased');
assert.equal(transientLeaseHarness.database.prepare(
  "SELECT COUNT(*) AS count FROM audit WHERE slot=? AND result='leased'",
).get(baseSlot).count, 1);
assert.equal(transientDispatchPosts, 0);
assert.doesNotMatch(JSON.stringify(transientFirstResult), new RegExp(transientLeaseMarker));

const transientSecondTime = baseSlot * 60_000 + 11 * 60_000 + 16_000;
const transientSecondResponse = await transientLeaseObject.fetch(
  boundaryRequest(transientSecondTime, transientSecondTime),
);
const transientSecondResult = await transientSecondResponse.json();
assert.equal(transientSecondResult.decision, 'would_dispatch');
assert.equal((await transientLeaseStore.getSlot(
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
)).phase, 'terminal');
assert.equal(transientLeaseHarness.database.prepare(
  "SELECT COUNT(*) AS count FROM audit WHERE slot=? AND result='leased'",
).get(baseSlot).count, 1);
assert.equal(transientDispatchPosts, 0);

const authorizedTransientStages = [
  { stage: 'read-auth', failureClass: 'transport', target: 'auth' },
  { stage: 'main-read', failureClass: 'rate-limit', target: '/commits/main' },
  { stage: 'native-inventory', failureClass: 'transport', target: '/315630665/runs' },
  { stage: 'canary-inventory', failureClass: 'rate-limit', target: '/344135917/runs' },
];
for (const { stage, failureClass, target } of authorizedTransientStages) {
  const stageHarness = sqliteHarness();
  const stageApi = apiHarness();
  const stageMarker = `synthetic-sensitive-${stage}-transient-detail`;
  let stageDispatchPosts = 0;
  const stageEnv = controllerEnv('observe', {
    AUTH_PROVIDER: target === 'auth'
      ? async () => { throw Object.assign(new Error(stageMarker), { failureClass }); }
      : authHarness(),
    FETCH_IMPL: async (url, options = {}) => {
      const value = String(url);
      if (value.includes('/actions/workflows/344170407/dispatches')) stageDispatchPosts += 1;
      if (target !== 'auth' && value.includes(target)) {
        if (failureClass === 'rate-limit') {
          return new Response('{}', { status: 429, headers: { 'Retry-After': '0' } });
        }
        throw new Error(stageMarker);
      }
      return stageApi.fetch(url, options);
    },
    GITHUB_REQUEST_OPTIONS: {
      sleep: async () => {},
      random: () => 0,
      timeoutSignal: () => new AbortController().signal,
    },
  });
  const stageObject = new ReleaseHealthControllerObject(stageHarness.state, stageEnv);
  const stageTime = baseSlot * 60_000 + 10 * 60_000 + 16_000;
  const stageResponse = await stageObject.fetch(boundaryRequest(stageTime, stageTime));
  const stageResult = await stageResponse.json();
  assert.deepEqual(stageResult, {
    decision: 'failed-closed',
    failure_class: failureClass,
    failure_stage: stage,
  }, stage);
  const stageStore = new ReleaseHealthSlotLedger(stageHarness.state, stageEnv);
  assert.equal((await stageStore.getSlot(
    baseSlot,
    controllerSourceDigest,
    controllerProfileDigest,
  )).phase, 'leased', stage);
  assert.equal(stageHarness.database.prepare(
    "SELECT COUNT(*) AS count FROM audit WHERE slot=? AND result='leased'",
  ).get(baseSlot).count, 1, stage);
  assert.equal(stageDispatchPosts, 0, stage);
  assert.doesNotMatch(JSON.stringify(stageResult), new RegExp(stageMarker), stage);
}

const disallowedTransientHarness = sqliteHarness();
const disallowedTransientApi = apiHarness();
const disallowedTransientMarker = 'synthetic-sensitive-fallback-inventory-transient-detail';
let disallowedTransientDispatchPosts = 0;
const disallowedTransientEnv = controllerEnv('observe', {
  AUTH_PROVIDER: authHarness(),
  FETCH_IMPL: async (url, options = {}) => {
    const value = String(url);
    if (value.includes('/actions/workflows/344170407/dispatches')) disallowedTransientDispatchPosts += 1;
    if (value.includes('/actions/workflows/344170407/runs')) throw new Error(disallowedTransientMarker);
    return disallowedTransientApi.fetch(url, options);
  },
  GITHUB_REQUEST_OPTIONS: {
    sleep: async () => {},
    random: () => 0,
    timeoutSignal: () => new AbortController().signal,
  },
});
const disallowedTransientObject = new ReleaseHealthControllerObject(
  disallowedTransientHarness.state,
  disallowedTransientEnv,
);
const disallowedTransientTime = baseSlot * 60_000 + 10 * 60_000 + 16_000;
const disallowedTransientResponse = await disallowedTransientObject.fetch(
  boundaryRequest(disallowedTransientTime, disallowedTransientTime),
);
const disallowedTransientResult = await disallowedTransientResponse.json();
assert.deepEqual(disallowedTransientResult, {
  decision: 'failed-closed',
  failure_class: 'transport',
  failure_stage: 'fallback-inventory',
});
const disallowedTransientStore = new ReleaseHealthSlotLedger(
  disallowedTransientHarness.state,
  disallowedTransientEnv,
);
assert.equal((await disallowedTransientStore.getSlot(
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
)).phase, 'terminal');
assert.equal(disallowedTransientDispatchPosts, 0);
assert.doesNotMatch(
  JSON.stringify({
    result: disallowedTransientResult,
    durable: await disallowedTransientStore.getSlot(
      baseSlot,
      controllerSourceDigest,
      controllerProfileDigest,
    ),
  }),
  new RegExp(disallowedTransientMarker),
);

const repeatedTransientHarness = sqliteHarness();
const repeatedTransientMarker = 'synthetic-sensitive-repeated-transient-detail';
const repeatedTransientEnv = controllerEnv('observe', {
  AUTH_PROVIDER: async () => {
    throw Object.assign(new Error(repeatedTransientMarker), { failureClass: 'transport' });
  },
  FETCH_IMPL: apiHarness().fetch,
});
const repeatedTransientObject = new ReleaseHealthControllerObject(
  repeatedTransientHarness.state,
  repeatedTransientEnv,
);
const repeatedAge13 = baseSlot * 60_000 + 13 * 60_000 + 16_000;
assert.deepEqual(await (await repeatedTransientObject.fetch(
  boundaryRequest(repeatedAge13, repeatedAge13),
)).json(), {
  decision: 'failed-closed',
  failure_class: 'transport',
  failure_stage: 'read-auth',
});
const repeatedTransientStore = new ReleaseHealthSlotLedger(repeatedTransientHarness.state, repeatedTransientEnv);
assert.equal((await repeatedTransientStore.getSlot(
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
)).phase, 'leased');
const repeatedAge14 = baseSlot * 60_000 + 14 * 60_000 + 16_000;
const repeatedAge14Result = await (await repeatedTransientObject.fetch(
  boundaryRequest(repeatedAge14, repeatedAge14),
)).json();
assert.deepEqual(repeatedAge14Result, {
  decision: 'failed-closed',
  failure_class: 'transport',
  failure_stage: 'read-auth',
});
assert.equal((await repeatedTransientStore.getSlot(
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
)).phase, 'terminal');
assert.equal(repeatedTransientHarness.database.prepare(
  "SELECT COUNT(*) AS count FROM audit WHERE slot=? AND result='leased'",
).get(baseSlot).count, 1);
assert.doesNotMatch(JSON.stringify({
  repeatedAge14Result,
  durable: await repeatedTransientStore.getSlot(baseSlot, controllerSourceDigest, controllerProfileDigest),
}), new RegExp(repeatedTransientMarker));

const finalMinuteHarness = sqliteHarness();
const finalMinuteMarker = 'synthetic-sensitive-final-minute-detail';
const finalMinuteEnv = controllerEnv('observe', {
  AUTH_PROVIDER: async () => {
    throw Object.assign(new Error(finalMinuteMarker), { failureClass: 'rate-limit' });
  },
  FETCH_IMPL: apiHarness().fetch,
});
const finalMinuteObject = new ReleaseHealthControllerObject(finalMinuteHarness.state, finalMinuteEnv);
const finalMinuteTime = baseSlot * 60_000 + 14 * 60_000 + 16_000;
const finalMinuteResponse = await finalMinuteObject.fetch(boundaryRequest(finalMinuteTime, finalMinuteTime));
const finalMinuteResult = await finalMinuteResponse.json();
assert.deepEqual(finalMinuteResult, {
  decision: 'failed-closed',
  failure_class: 'rate-limit',
  failure_stage: 'read-auth',
});
const finalMinuteStore = new ReleaseHealthSlotLedger(finalMinuteHarness.state, finalMinuteEnv);
assert.equal((await finalMinuteStore.getSlot(
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
)).phase, 'terminal');
assert.doesNotMatch(JSON.stringify({
  finalMinuteResult,
  durable: await finalMinuteStore.getSlot(baseSlot, controllerSourceDigest, controllerProfileDigest),
}), new RegExp(finalMinuteMarker));

const forbiddenScopeHarness = sqliteHarness();
let forbiddenScopeCalls = 0;
const forbiddenScopeEnv = controllerEnv('observe', {
  AUTH_PROVIDER: async (fetchImpl, _env, _now, permissionMode) => createInstallationAccessToken(
    fetchImpl,
    '12345',
    'synthetic-app-jwt',
    permissionMode,
    { sleep: async () => {}, timeoutSignal: () => new AbortController().signal },
  ),
  FETCH_IMPL: async () => {
    forbiddenScopeCalls += 1;
    return new Response('{}', { status: 403 });
  },
});
const forbiddenScopeObject = new ReleaseHealthControllerObject(forbiddenScopeHarness.state, forbiddenScopeEnv);
const forbiddenScopeTime = baseSlot * 60_000 + 10 * 60_000 + 16_000;
const forbiddenScopeResponse = await forbiddenScopeObject.fetch(
  boundaryRequest(forbiddenScopeTime, forbiddenScopeTime),
);
assert.deepEqual(await forbiddenScopeResponse.json(), {
  decision: 'failed-closed',
  failure_class: 'provider-evidence',
  failure_stage: 'read-auth',
});
assert.equal(forbiddenScopeCalls, 1);
const forbiddenScopeStore = new ReleaseHealthSlotLedger(forbiddenScopeHarness.state, forbiddenScopeEnv);
assert.equal((await forbiddenScopeStore.getSlot(
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
)).phase, 'terminal');

const redirectAuthHarness = sqliteHarness();
let redirectAuthCalls = 0;
let redirectAuthDispatchPosts = 0;
const redirectAuthEnv = controllerEnv('observe', {
  AUTH_PROVIDER: async (fetchImpl, _env, _now, permissionMode) => createInstallationAccessToken(
    fetchImpl,
    '12345',
    'synthetic-app-jwt',
    permissionMode,
    { sleep: async () => {}, timeoutSignal: () => new AbortController().signal },
  ),
  FETCH_IMPL: async (url, options) => {
    if (String(url).includes('/actions/workflows/344170407/dispatches')) {
      redirectAuthDispatchPosts += 1;
    }
    redirectAuthCalls += 1;
    assert.equal(options.redirect, 'manual');
    return new Response('', {
      status: 302,
      headers: { Location: 'https://redirect-target.invalid/credential-capture' },
    });
  },
});
const redirectAuthObject = new ReleaseHealthControllerObject(redirectAuthHarness.state, redirectAuthEnv);
const redirectAuthTime = baseSlot * 60_000 + 10 * 60_000 + 16_000;
const redirectAuthResponse = await redirectAuthObject.fetch(
  boundaryRequest(redirectAuthTime, redirectAuthTime),
);
assert.deepEqual(await redirectAuthResponse.json(), {
  decision: 'failed-closed',
  failure_class: 'provider-evidence',
  failure_stage: 'read-auth',
});
assert.equal(redirectAuthCalls, 1);
assert.equal(redirectAuthDispatchPosts, 0);

// Closed, redacted failure stages identify the exact eligible boundary without provider details.
assert.ok(failureStages.length >= 12);
assert.equal(new Set(failureStages).size, failureStages.length);
assert.ok(failureStages.every((stage) => /^[a-z][a-z0-9-]{2,31}$/.test(stage)));
assert.doesNotMatch(failureStages.join(','), /token|signature|private|hmac|authorization|url|body|request/i);
assert.equal(sanitizedFailureStage('not-allowlisted'), 'runtime-boundary');
assert.equal(sanitizedFailureStage('not-allowlisted', 'also-not-allowlisted'), 'runtime-boundary');
const diagnosticHarness = sqliteHarness();
const diagnosticLogs = [];
const diagnosticApi = apiHarness();
const sensitiveMarker = 'synthetic-sensitive-provider-detail';
const diagnosticEnv = controllerEnv('observe', {
  AUTH_PROVIDER: authHarness(),
  FETCH_IMPL: async (url, options) => {
    if (String(url).includes('/actions/workflows/315630665/runs')) {
      const error = new Error(sensitiveMarker);
      error.name = 'TimeoutError';
      error.stack = `${sensitiveMarker} stack`;
      error.url = `https://provider.invalid/${sensitiveMarker}`;
      error.body = sensitiveMarker;
      error.requestId = sensitiveMarker;
      error.failureStage = 'write-auth';
      throw error;
    }
    return diagnosticApi.fetch(url, options);
  },
  GITHUB_REQUEST_OPTIONS: {
    random: () => 0,
    sleep: async () => {},
    timeoutSignal: () => new AbortController().signal,
  },
  STRUCTURED_LOG: (line) => diagnosticLogs.push(JSON.parse(line)),
});
const diagnosticObject = new ReleaseHealthControllerObject(diagnosticHarness.state, diagnosticEnv);
const diagnosticTime = at('2026-08-27T20:15:16Z');
const diagnosticResponse = await diagnosticObject.fetch(boundaryRequest(diagnosticTime, diagnosticTime));
const diagnosticResult = await diagnosticResponse.json();
assert.equal(diagnosticResponse.status, 200);
assert.deepEqual(diagnosticResult, {
  decision: 'failed-closed',
  failure_class: 'transport',
  failure_stage: 'native-inventory',
});
const diagnosticStore = new ReleaseHealthSlotLedger(diagnosticHarness.state, diagnosticEnv);
assert.deepEqual(
  (await diagnosticStore.getSlot(baseSlot, controllerSourceDigest, controllerProfileDigest)).result,
  diagnosticResult,
);
assert.deepEqual(diagnosticLogs.at(-1), {
  component: 'release-health-controller',
  event: 'evaluation-completed',
  decision: 'failed-closed',
  activation_proof: null,
  failure_class: 'transport',
  failure_stage: 'native-inventory',
});
const requestAttemptLogs = diagnosticLogs.filter(({ event }) => event === 'github-request-attempt');
assert.equal(requestAttemptLogs.length, 4);
assert.ok(requestAttemptLogs.every((event) => (
  JSON.stringify(Object.keys(event).sort()) === JSON.stringify(diagnosticKeys)
)));
assert.deepEqual(requestAttemptLogs.slice(-3).map((event) => ({
  attempt: event.attempt,
  operation_kind: event.operation_kind,
  phase: event.phase,
  status: event.status,
  consumer: event.consumer,
  outcome: event.outcome,
})), [1, 2, 3].map((attempt) => ({
  attempt,
  operation_kind: 'read',
  phase: 'headers',
  status: null,
  consumer: 'stream',
  outcome: 'transport',
})));
assert.doesNotMatch(JSON.stringify({ diagnosticResult, diagnosticLogs }), new RegExp(sensitiveMarker));

const invalidAuthHarness = sqliteHarness();
const invalidAuthEnv = controllerEnv('observe', {
  AUTH_PROVIDER: async (_fetch, _env, now) => ({
    token: sensitiveMarker,
    expiresAt: now + 3600,
    permissionMode: 'write',
  }),
  FETCH_IMPL: apiHarness().fetch,
});
const invalidAuthObject = new ReleaseHealthControllerObject(invalidAuthHarness.state, invalidAuthEnv);
const invalidAuthResponse = await invalidAuthObject.fetch(boundaryRequest(diagnosticTime, diagnosticTime));
assert.deepEqual(await invalidAuthResponse.json(), {
  decision: 'failed-closed',
  failure_class: 'configuration',
  failure_stage: 'read-auth',
});

const nestedAuthHarness = sqliteHarness();
const nestedAuthStore = new ReleaseHealthSlotLedger(nestedAuthHarness.state, { MODE: 'observe' });
const nestedAuthProof = await seedActivation(
  nestedAuthStore,
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
);
const nestedAuthPendingSlot = baseSlot + 30;
await prepare(
  nestedAuthStore,
  nestedAuthPendingSlot,
  controllerSourceDigest,
  controllerProfileDigest,
  'd',
);
assert.equal((await nestedAuthStore.consumePostPermit(
  nestedAuthPendingSlot,
  controllerSourceDigest,
  controllerProfileDigest,
  nestedAuthProof,
  nestedAuthPendingSlot * 60 + 600,
  nestedAuthPendingSlot * 60_000 + 600_000,
)).permit, true);
const nestedAuthEnv = controllerEnv('observe', {
  AUTH_PROVIDER: invalidAuthEnv.AUTH_PROVIDER,
  FETCH_IMPL: apiHarness().fetch,
});
const nestedAuthObject = new ReleaseHealthControllerObject(nestedAuthHarness.state, nestedAuthEnv);
const nestedAuthTime = (nestedAuthPendingSlot + 15) * 60_000 + 600_000;
const nestedAuthResponse = await nestedAuthObject.fetch(boundaryRequest(nestedAuthTime, nestedAuthTime));
assert.equal(nestedAuthResponse.status, 503);
assert.deepEqual(await nestedAuthResponse.json(), {
  decision: 'failed-closed',
  failure_class: 'configuration',
  failure_stage: 'read-auth',
});

const failureRecordHarness = sqliteHarness();
const failureRecordEnv = controllerEnv('observe', {
  AUTH_PROVIDER: authHarness(),
  FETCH_IMPL: diagnosticEnv.FETCH_IMPL,
  GITHUB_REQUEST_OPTIONS: diagnosticEnv.GITHUB_REQUEST_OPTIONS,
});
const failureRecordObject = new ReleaseHealthControllerObject(failureRecordHarness.state, failureRecordEnv);
failureRecordObject.recordFailureTerminal = async () => {
  const error = new Error(sensitiveMarker);
  error.name = 'TimeoutError';
  error.stack = `${sensitiveMarker} stack`;
  throw error;
};
const failureRecordResponse = await failureRecordObject.fetch(boundaryRequest(diagnosticTime, diagnosticTime));
const failureRecordResult = await failureRecordResponse.json();
assert.equal(failureRecordResponse.status, 503);
assert.deepEqual(failureRecordResult, {
  decision: 'failed-closed',
  failure_class: 'transport',
  failure_stage: 'failure-record',
});
assert.doesNotMatch(JSON.stringify(failureRecordResult), new RegExp(sensitiveMarker));

healthHarness.database.prepare(`INSERT INTO alert_outbox(
  alert_id,slot,source_digest,profile_digest,body,state,attempts,next_attempt_ms,
  created_at_ms,updated_at_ms
) VALUES(?,?,?,?,?,'dead',8,?,?,?)`).run(
  'f'.repeat(64),
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
  '{}',
  healthClock,
  healthClock,
  healthClock,
);
healthClock = at('2026-08-27T20:02:30Z');
publicHealth = await worker.fetch(publicHealthRequest(), healthEnv);
publicHealthBody = await publicHealth.json();
assert.equal(publicHealth.status, 503);
assert.equal(publicHealthBody.alerts.dead, 1);
assert.equal(publicHealthBody.checks.no_dead_alerts, false);
assert.ok(healthLogs.some((entry) => entry.event === 'health-check' && entry.status === 503));

// Actual Durable Object /evaluate serialization, observe activation, and active dispatch.
const boundaryHarness = sqliteHarness();
const observeApi = apiHarness();
const authModes = [];
let uuidCounter = 6;
const logs = [];
const observeEnv = controllerEnv('observe', {
  FETCH_IMPL: observeApi.fetch,
  AUTH_PROVIDER: authHarness(authModes),
  RANDOM_UUID: () => `${String(uuidCounter++).repeat(8).slice(0, 8)}6666-4666-8666-666666666666`,
  STRUCTURED_LOG: (line) => logs.push(JSON.parse(line)),
});
let object = new ReleaseHealthControllerObject(boundaryHarness.state, observeEnv);
assert.equal((await object.fetch(new Request('https://controller.internal/wrong', { method: 'POST' }))).status, 404);
assert.equal((await object.fetch(new Request('https://controller.internal/evaluate', { method: 'GET' }))).status, 405);
assert.equal((await object.fetch(new Request('https://controller.internal/evaluate', {
  method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}',
}))).status, 415);
assert.equal((await object.fetch(new Request('https://controller.internal/evaluate', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scheduledTime: 1, nowMs: 1, extra: 1 }),
}))).status, 400);
const [firstBoundary, concurrentBoundary] = await Promise.all([
  object.fetch(boundaryRequest(at('2026-08-27T20:15:16Z'), at('2026-08-27T20:15:16Z'))),
  object.fetch(boundaryRequest(at('2026-08-27T20:15:16Z'), at('2026-08-27T20:15:16Z'))),
]);
assert.equal(firstBoundary.status, 200);
assert.equal((await firstBoundary.json()).decision, 'would_dispatch');
assert.equal(concurrentBoundary.status, 200);
assert.equal((await concurrentBoundary.json()).decision, 'would_dispatch');
object = new ReleaseHealthControllerObject(boundaryHarness.state, observeEnv);
const secondBoundary = await object.fetch(boundaryRequest(
  at('2026-08-27T20:30:16Z'), at('2026-08-27T20:30:16Z'),
));
const secondBoundaryResult = await secondBoundary.json();
assert.match(secondBoundaryResult.activation_proof, /^[a-f0-9]{64}$/);
assert.deepEqual([...new Set(authModes)], ['read']);
assert.equal(observeApi.calls.some((call) => call.method === 'POST'), false);
const evaluationLogs = logs.filter(({ event }) => event === 'evaluation-completed');
assert.ok(evaluationLogs.length > 0);
assert.ok(evaluationLogs.every((line) => (
  Object.keys(line).sort().join(',') === 'activation_proof,component,decision,event,failure_class,failure_stage'
  && line.event === 'evaluation-completed'
  && line.failure_class === null
  && line.failure_stage === null
)));
const githubAttemptLogs = logs.filter(({ event }) => event === 'github-request-attempt');
assert.ok(githubAttemptLogs.length > 0);
assert.ok(githubAttemptLogs.every((line) => (
  JSON.stringify(Object.keys(line).sort()) === JSON.stringify(diagnosticKeys)
  && line.outcome === 'success'
)));

const activeApi = apiHarness({
  fallbackInventories: [[]],
  dispatch: [new Response(JSON.stringify(receipt(9300)), { status: 200 })],
});
const activeModes = [];
const activeEnv = controllerEnv('active', {
  FETCH_IMPL: activeApi.fetch,
  AUTH_PROVIDER: authHarness(activeModes),
  ACTIVATION_PROOF: secondBoundaryResult.activation_proof,
  RANDOM_UUID: () => '77777777-7777-4777-8777-777777777777',
});
object = new ReleaseHealthControllerObject(boundaryHarness.state, activeEnv);
const activeResponse = await object.fetch(boundaryRequest(
  at('2026-08-27T20:45:16Z'), at('2026-08-27T20:45:16Z'),
));
assert.equal(activeResponse.status, 200);
assert.equal((await activeResponse.json()).decision, 'dispatched');
assert.deepEqual(activeModes, ['read', 'write']);
assert.equal(activeApi.calls.filter((call) => (
  call.method === 'POST' && call.url.includes('/actions/workflows/344170407/dispatches')
)).length, 1);

const signingHarness = sqliteHarness();
const signingStore = new ReleaseHealthSlotLedger(signingHarness.state, { MODE: 'observe' });
const signingProof = await seedActivation(
  signingStore,
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
);
const signingApi = apiHarness({ fallbackInventories: [[]] });
const signingRequestId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const signingEnv = controllerEnv('active', {
  FETCH_IMPL: signingApi.fetch,
  AUTH_PROVIDER: authHarness([]),
  ACTIVATION_PROOF: signingProof,
  ADMISSION_HMAC_KEY: sensitiveMarker,
  RANDOM_UUID: () => signingRequestId,
});
const signingObject = new ReleaseHealthControllerObject(signingHarness.state, signingEnv);
const signingTime = (baseSlot + 30) * 60_000 + 600_000;
const signingResponse = await signingObject.fetch(boundaryRequest(signingTime, signingTime));
const signingResult = await signingResponse.json();
assert.deepEqual(signingResult, {
  decision: 'dispatch-unknown',
  request_id: signingRequestId.replaceAll('-', ''),
  failure_class: 'internal',
  failure_stage: 'dispatch-prepare',
});
assert.equal(signingApi.calls.filter((call) => (
  call.method === 'POST' && call.url.includes('/actions/workflows/344170407/dispatches')
)).length, 0);
assert.doesNotMatch(JSON.stringify(signingResult), new RegExp(sensitiveMarker));

const confirmedHarness = sqliteHarness();
const confirmedStore = new ReleaseHealthSlotLedger(confirmedHarness.state, { MODE: 'observe' });
const confirmedProof = await seedActivation(
  confirmedStore,
  baseSlot,
  controllerSourceDigest,
  controllerProfileDigest,
);
const confirmedSlot = baseSlot + 30;
const confirmedApi = apiHarness({
  fallbackInventories: [[]],
  dispatch: [new Response(JSON.stringify(receipt(9350)), { status: 200 })],
});
const confirmedEnv = controllerEnv('active', {
  FETCH_IMPL: confirmedApi.fetch,
  AUTH_PROVIDER: authHarness([]),
  ACTIVATION_PROOF: confirmedProof,
  RANDOM_UUID: () => '88888888-8888-4888-8888-888888888888',
});
object = new ReleaseHealthControllerObject(confirmedHarness.state, confirmedEnv);
const terminalizeConfirmed = object.terminalizeConfirmed.bind(object);
let terminalizationFailures = 1;
object.terminalizeConfirmed = async (...arguments_) => {
  if (terminalizationFailures > 0) {
    terminalizationFailures -= 1;
    throw new Error('synthetic terminalization failure');
  }
  return terminalizeConfirmed(...arguments_);
};
const confirmedBoundary = await object.fetch(boundaryRequest(
  confirmedSlot * 60_000 + 600_000,
  confirmedSlot * 60_000 + 600_000,
));
const confirmedBoundaryResult = await confirmedBoundary.json();
const confirmedAfterFailure = await confirmedStore.getSlot(
  confirmedSlot, controllerSourceDigest, controllerProfileDigest,
);
assert.equal(confirmedAfterFailure.phase, 'terminal', JSON.stringify(confirmedAfterFailure));
assert.equal(confirmedBoundary.status, 200, JSON.stringify(confirmedBoundaryResult));
assert.equal(confirmedBoundaryResult.decision, 'dispatched');
object = new ReleaseHealthControllerObject(confirmedHarness.state, confirmedEnv);
const confirmedRestart = await object.fetch(boundaryRequest(
  confirmedSlot * 60_000 + 660_000,
  confirmedSlot * 60_000 + 660_000,
));
assert.equal(confirmedRestart.status, 200);
assert.equal((await confirmedRestart.json()).decision, 'dispatched');
assert.equal((await confirmedStore.getSlot(
  confirmedSlot, controllerSourceDigest, controllerProfileDigest,
)).phase, 'terminal');
assert.equal(confirmedApi.calls.filter((call) => (
  call.method === 'POST' && call.url.includes('/actions/workflows/344170407/dispatches')
)).length, 1);

// Restart before POST reuses the unsigned request; restart after POST is GET-only and tolerates indexing lag.
const recoveryHarness = sqliteHarness();
let recoveryStore = new ReleaseHealthSlotLedger(recoveryHarness.state, { MODE: 'observe' });
const recoveryProof = await seedActivation(recoveryStore, baseSlot, controllerSourceDigest, controllerProfileDigest);
const dispatchSlot = baseSlot + 30;
const preparedEnvelope = await prepare(
  recoveryStore, dispatchSlot, controllerSourceDigest, controllerProfileDigest, '8',
);
const fallbackRun = runEvidence({
  id: 9400,
  workflowId: 344170407,
  path: '.github/workflows/release-health-monitor-fallback.yml@refs/heads/main',
  event: 'workflow_dispatch',
  createdAt: new Date(dispatchSlot * 60_000 + 600_000).toISOString(),
  displayTitle: `Release health independent fallback [slot:${dispatchSlot} request:${preparedEnvelope.request_id}]`,
});
const wrongShaRun = runEvidence({
  id: 9398,
  workflowId: 344170407,
  path: '.github/workflows/release-health-monitor-fallback.yml@refs/heads/main',
  event: 'workflow_dispatch',
  sha: '2'.repeat(40),
  createdAt: new Date(dispatchSlot * 60_000 + 600_000).toISOString(),
  displayTitle: `Release health independent fallback [slot:${dispatchSlot} request:${preparedEnvelope.request_id}]`,
});
const wrongSlotRun = runEvidence({
  id: 9399,
  workflowId: 344170407,
  path: '.github/workflows/release-health-monitor-fallback.yml@refs/heads/main',
  event: 'workflow_dispatch',
  createdAt: new Date(dispatchSlot * 60_000 + 600_000).toISOString(),
  displayTitle: `Release health independent fallback [slot:${dispatchSlot + 15} request:${preparedEnvelope.request_id}]`,
});
const recoveryApi = apiHarness({
  fallbackInventories: [
    [],
    [wrongShaRun, wrongSlotRun],
    Object.assign(new Error(sensitiveMarker), { name: 'TimeoutError' }),
    Object.assign(new Error(sensitiveMarker), { name: 'TimeoutError' }),
    Object.assign(new Error(sensitiveMarker), { name: 'TimeoutError' }),
    [fallbackRun],
  ],
  dispatch: [new Error('synthetic uncertain transport')],
  alerts: [new Error('synthetic alert sink failure'), new Response('', { status: 202 })],
});
const recoveryModes = [];
const recoveryEnv = controllerEnv('active', {
  FETCH_IMPL: recoveryApi.fetch,
  AUTH_PROVIDER: authHarness(recoveryModes),
  ACTIVATION_PROOF: recoveryProof,
});
object = new ReleaseHealthControllerObject(recoveryHarness.state, recoveryEnv);
const uncertain = await object.fetch(boundaryRequest(
  dispatchSlot * 60_000 + 840_000,
  dispatchSlot * 60_000 + 840_000,
));
assert.equal((await uncertain.json()).decision, 'dispatch-unknown');
assert.equal((await recoveryStore.getSlot(
  dispatchSlot, controllerSourceDigest, controllerProfileDigest,
)).post_attempt_count, 1);
const workflowPostCount = () => recoveryApi.calls.filter((call) => (
  call.method === 'POST' && call.url.includes('/actions/workflows/344170407/dispatches')
)).length;
assert.equal(workflowPostCount(), 1);
const firstAlertId = recoveryApi.calls.find((call) => call.url.includes('alerts.scalesmall.ai'))
  .options.headers['X-SSAI-Alert-Id'];
object = new ReleaseHealthControllerObject(recoveryHarness.state, recoveryEnv);
await object.fetch(boundaryRequest(
  dispatchSlot * 60_000 + 600_000,
  dispatchSlot * 60_000 + 1_140_000,
));
assert.equal(workflowPostCount(), 1);
const recoveryAfterIndexingLag = await recoveryStore.getSlot(
  dispatchSlot, controllerSourceDigest, controllerProfileDigest,
);
assert.equal(recoveryAfterIndexingLag.phase, 'unknown');
assert.equal(recoveryAfterIndexingLag.result.failure_stage, 'fallback-dispatch');
const alertIds = recoveryApi.calls
  .filter((call) => call.url.includes('alerts.scalesmall.ai'))
  .map((call) => call.options.headers['X-SSAI-Alert-Id']);
assert.ok(alertIds.filter((value) => value === firstAlertId).length >= 2);
object = new ReleaseHealthControllerObject(recoveryHarness.state, recoveryEnv);
await object.fetch(boundaryRequest(
  dispatchSlot * 60_000 + 600_000,
  dispatchSlot * 60_000 + 1_740_000,
));
assert.equal(workflowPostCount(), 1);
const recoveryAfterReadFailure = await recoveryStore.getSlot(
  dispatchSlot, controllerSourceDigest, controllerProfileDigest,
);
assert.equal(recoveryAfterReadFailure.phase, 'unknown');
assert.equal(recoveryAfterReadFailure.result.failure_stage, 'fallback-inventory');
assert.doesNotMatch(JSON.stringify(recoveryAfterReadFailure.result), new RegExp(sensitiveMarker));
object = new ReleaseHealthControllerObject(recoveryHarness.state, recoveryEnv);
await object.fetch(boundaryRequest(
  dispatchSlot * 60_000 + 600_000,
  dispatchSlot * 60_000 + 2_940_000,
));
assert.equal(workflowPostCount(), 1);
assert.equal((await recoveryStore.getSlot(
  dispatchSlot, controllerSourceDigest, controllerProfileDigest,
)).result.decision, 'dispatch-reconciled');

const crashHarness = sqliteHarness();
const crashStore = new ReleaseHealthSlotLedger(crashHarness.state, { MODE: 'active' });
const crashProof = await seedActivation(crashStore, baseSlot, controllerSourceDigest, controllerProfileDigest);
const crashSlot = baseSlot + 30;
await prepare(crashStore, crashSlot, controllerSourceDigest, controllerProfileDigest, '9');
assert.equal((await crashStore.consumePostPermit(
  crashSlot,
  controllerSourceDigest,
  controllerProfileDigest,
  crashProof,
  crashSlot * 60 + 600,
  crashSlot * 60_000 + 600_000,
)).permit, true);
const crashApi = apiHarness({ fallbackInventories: [[]] });
object = new ReleaseHealthControllerObject(crashHarness.state, controllerEnv('active', {
  FETCH_IMPL: crashApi.fetch,
  AUTH_PROVIDER: authHarness([]),
  ACTIVATION_PROOF: crashProof,
}));
await object.fetch(boundaryRequest(crashSlot * 60_000 + 840_000, crashSlot * 60_000 + 840_000));
assert.equal(crashApi.calls.some((call) => (
  call.method === 'POST' && call.url.includes('/actions/workflows/344170407/dispatches')
)), false);
assert.equal((await crashStore.getSlot(
  crashSlot, controllerSourceDigest, controllerProfileDigest,
)).phase, 'unknown');

// Digest/profile binding and checked-in digest closure.
assert.notEqual(await activationProof(sourceA, profileA, [
  { slot: baseSlot, audit_hash: '1'.repeat(64) },
  { slot: baseSlot + 15, audit_hash: '2'.repeat(64) },
]), await activationProof(sourceB, profileA, [
  { slot: baseSlot, audit_hash: '1'.repeat(64) },
  { slot: baseSlot + 15, audit_hash: '2'.repeat(64) },
]));
assert.notEqual(await chainedAuditHash('', { decision: 'one' }), await chainedAuditHash('', { decision: 'two' }));
assert.match(await sha256Hex('domain', 'value'), /^[a-f0-9]{64}$/);
assert.throws(() => publicAuditEvent({ authorization: 'x' }), /prohibited/);
assert.equal(controllerConfig.vars.CONTROLLER_SOURCE_SHA256, controllerSourceDigest);
assert.equal(controllerConfig.vars.CONTROLLER_ACTIVATION_PROFILE_SHA256, controllerProfileDigest);
assert.equal(controllerConfig.vars.MODE, 'observe');
assert.deepEqual(controllerConfig.triggers.crons, ['* * * * *']);
assert.equal(controllerConfig.workers_dev, false);
assert.deepEqual(controllerConfig.routes, [{
  pattern: 'release-health-controller.scalesmall.ai',
  custom_domain: true,
}]);
assert.equal(controllerConfig.observability.enabled, true);
assert.equal(controllerConfig.observability.logs.enabled, true);
assert.equal(controllerConfig.observability.logs.invocation_logs, true);
assert.equal(controllerConfig.vars.HEALTH_ROUTE, 'https://release-health-controller.scalesmall.ai/healthz');
assert.equal(controllerConfig.vars.HEALTH_STALE_AFTER_SECONDS, '300');

console.log('Release-health controller deterministic tests passed.');
