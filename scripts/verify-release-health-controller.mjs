import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import {
  currentLogicalSlot,
  evaluationWindow,
  exactNativeBlocker,
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
  githubApi,
  validateDispatchReceipt,
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
        const runs = fallbackInventories[Math.min(fallbackIndex, fallbackInventories.length - 1)] || [];
        fallbackIndex += 1;
        return new Response(JSON.stringify(payload(runs)), { status: 200 });
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
  sourceHash.update(`${name}\0`).update(source).update('\0');
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
for (const minuteOffset of [10, 11, 12, 13, 14]) {
  const tick = baseSlot * 60_000 + minuteOffset * 60_000;
  assert.equal(evaluationWindow(tick, baseSlot, tick).eligible, true);
}
assert.equal(evaluationWindow(baseSlot * 60_000 + 9 * 60_000, baseSlot).eligible, false);
assert.equal(evaluationWindow(baseSlot * 60_000 + 15 * 60_000, baseSlot).eligible, false);
assert.equal(evaluationWindow(at('2026-08-27T20:16:00Z'), baseSlot, at('2026-08-27T20:15:00Z')).eligible, false);
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
let retryCalls = 0;
const retryDelays = [];
const retryResult = await githubApi(async (_url, options) => {
  retryCalls += 1;
  assert.equal(options.method, 'GET');
  assert.equal(options.redirect, 'error');
  assert.deepEqual(Object.keys(options.headers).sort(), ['Accept', 'Authorization', 'X-GitHub-Api-Version'].sort());
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
const tokenValue = await createInstallationAccessToken(async (_url, options) => {
  tokenCalls += 1;
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
  sleep: async () => {},
  timeoutSignal: () => new AbortController().signal,
});
assert.equal(tokenCalls, 2);
assert.equal(tokenValue.permissionMode, 'read');
let writeTokenCalls = 0;
const writeTokenValue = await createInstallationAccessToken(async (_url, options) => {
  writeTokenCalls += 1;
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
  assert.equal(options.redirect, 'error');
  throw new DOMException('synthetic timeout', 'TimeoutError');
}, 'synthetic-write-token', dispatchInputs, { timeoutSignal: () => new AbortController().signal });
assert.equal(dispatchCalls, 1);
assert.equal(ambiguous.outcome, 'ambiguous');
assert.equal(ambiguous.failure_class, 'transport');
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

// Actual Durable Object /evaluate boundary, serialization, observe activation, and active dispatch.
assert.equal(worker.fetch, undefined);
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
  object.fetch(boundaryRequest(at('2026-08-27T20:15:00Z'), at('2026-08-27T20:15:00Z'))),
  object.fetch(boundaryRequest(at('2026-08-27T20:15:00Z'), at('2026-08-27T20:15:00Z'))),
]);
assert.equal(firstBoundary.status, 200);
assert.equal((await firstBoundary.json()).decision, 'would_dispatch');
assert.equal(concurrentBoundary.status, 200);
assert.equal((await concurrentBoundary.json()).decision, 'would_dispatch');
object = new ReleaseHealthControllerObject(boundaryHarness.state, observeEnv);
const secondBoundary = await object.fetch(boundaryRequest(
  at('2026-08-27T20:30:00Z'), at('2026-08-27T20:30:00Z'),
));
const secondBoundaryResult = await secondBoundary.json();
assert.match(secondBoundaryResult.activation_proof, /^[a-f0-9]{64}$/);
assert.deepEqual([...new Set(authModes)], ['read']);
assert.equal(observeApi.calls.some((call) => call.method === 'POST'), false);
assert.ok(logs.every((line) => Object.keys(line).sort().join(',') === 'activation_proof,component,decision'));

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
  at('2026-08-27T20:45:00Z'), at('2026-08-27T20:45:00Z'),
));
assert.equal(activeResponse.status, 200);
assert.equal((await activeResponse.json()).decision, 'dispatched');
assert.deepEqual(activeModes, ['read', 'write']);
assert.equal(activeApi.calls.filter((call) => (
  call.method === 'POST' && call.url.includes('/actions/workflows/344170407/dispatches')
)).length, 1);

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
  fallbackInventories: [[], [wrongShaRun, wrongSlotRun], [fallbackRun]],
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
assert.equal((await recoveryStore.getSlot(
  dispatchSlot, controllerSourceDigest, controllerProfileDigest,
)).phase, 'unknown');
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

console.log('Release-health controller deterministic tests passed.');
