import { evaluateSlot, failureStages } from './controller.mjs';
import { ReleaseHealthSlotLedger } from './store.mjs';

export { ReleaseHealthSlotLedger };

const publicHostname = 'release-health-controller.scalesmall.ai';
const structuredFailureClasses = new Set([
  'provider-evidence',
  'transport',
  'rate-limit',
  'dispatch-unknown',
  'circuit-open',
  'configuration',
  'internal',
  'prepared-expired',
]);
const structuredFailureStages = new Set(failureStages);

function healthStaleAfterMs(env) {
  if (env.HEALTH_ROUTE !== `https://${publicHostname}/healthz` || env.HEALTH_STALE_AFTER_SECONDS !== '300') {
    throw new Error('Controller health policy is invalid.');
  }
  return 300_000;
}

function runtimeNow(env) {
  const value = env.CLOCK_NOW ? env.CLOCK_NOW() : Date.now();
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Controller runtime clock is invalid.');
  return value;
}

function noStoreJson(value, status = 200) {
  return Response.json(value, {
    status,
    headers: {
      'Cache-Control': 'no-store, max-age=0',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function logStructured(env, value) {
  (env.STRUCTURED_LOG || console.log)(JSON.stringify(Object.freeze({
    component: 'release-health-controller',
    ...value,
  })));
}

async function boundedJsonRequest(request, maximum = 512) {
  const length = request.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maximum)) {
    throw new Error('Controller request is oversized.');
  }
  if (!request.body) throw new Error('Controller request body is missing.');
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) {
        await reader.cancel();
        throw new Error('Controller request is oversized.');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error('Controller request body is invalid.');
  }
  if (
    !value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== 'nowMs,scheduledTime'
    || !Number.isSafeInteger(value.scheduledTime) || !Number.isSafeInteger(value.nowMs)
    || value.scheduledTime < 0 || value.nowMs < 0
  ) throw new Error('Controller request body is invalid.');
  return value;
}

function structuredDecision(result) {
  const decision = /^[a-z][a-z0-9_-]{2,47}$/.test(String(result?.decision ?? ''))
    ? result.decision
    : 'failed-closed';
  const activationProof = /^[a-f0-9]{64}$/.test(String(result?.activation_proof ?? ''))
    ? result.activation_proof
    : null;
  const failureClass = structuredFailureClasses.has(result?.failure_class)
    ? result.failure_class
    : null;
  const failureStage = structuredFailureStages.has(result?.failure_stage)
    ? result.failure_stage
    : null;
  return Object.freeze({
    event: 'evaluation-completed',
    decision,
    activation_proof: activationProof,
    failure_class: failureClass,
    failure_stage: failureStage,
  });
}

function boundaryFailureResult(error) {
  const candidate = error?.result;
  const failureClass = structuredFailureClasses.has(candidate?.failure_class)
    ? candidate.failure_class
    : structuredFailureClasses.has(error?.failureClass) ? error.failureClass : 'internal';
  const failureStage = structuredFailureStages.has(candidate?.failure_stage)
    ? candidate.failure_stage
    : structuredFailureStages.has(error?.failureStage) ? error.failureStage : 'runtime-boundary';
  return Object.freeze({
    decision: 'failed-closed',
    failure_class: failureClass,
    failure_stage: failureStage,
  });
}

function publicDigest(value) {
  return /^[a-f0-9]{64}$/.test(String(value ?? '')) ? value : null;
}

function publicMode(value) {
  return ['observe', 'active'].includes(value) ? value : null;
}

function publicHealthBody(env, status = null) {
  const sourceDigest = publicDigest(env.CONTROLLER_SOURCE_SHA256);
  const profileDigest = publicDigest(env.CONTROLLER_ACTIVATION_PROFILE_SHA256);
  if (!status) {
    return Object.freeze({
      schema: 'ssai-release-health-controller-health-v1',
      component: 'release-health-controller',
      status: 'unhealthy',
      mode: publicMode(env.MODE),
      last_completed_tick: null,
      last_scheduled_time: null,
      last_decision: null,
      source_digest: sourceDigest,
      profile_digest: profileDigest,
      config_digest: publicDigest(env.CONTROLLER_CONFIG_SHA256),
      alerts: Object.freeze({ pending: 0, dead: 0 }),
      checks: Object.freeze({
        fresh: false,
        no_dead_alerts: true,
        no_terminal_failure: false,
        no_internal_failure: false,
      }),
    });
  }
  return Object.freeze({
    schema: 'ssai-release-health-controller-health-v1',
    component: 'release-health-controller',
    status: status.healthy ? 'healthy' : 'unhealthy',
    mode: publicMode(env.MODE),
    last_completed_tick: status.last_completed_tick_ms === null
      ? null : new Date(status.last_completed_tick_ms).toISOString(),
    last_scheduled_time: status.last_scheduled_time_ms === null
      ? null : new Date(status.last_scheduled_time_ms).toISOString(),
    last_decision: status.last_decision,
    source_digest: sourceDigest,
    profile_digest: profileDigest,
    config_digest: publicDigest(env.CONTROLLER_CONFIG_SHA256),
    alerts: Object.freeze({ pending: status.pending_alerts, dead: status.dead_alerts }),
    checks: Object.freeze({
      fresh: status.fresh,
      no_dead_alerts: status.dead_alerts === 0,
      no_terminal_failure: !status.terminal_failure,
      no_internal_failure: !status.internal_failure,
    }),
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (
      url.protocol !== 'https:' || url.hostname !== publicHostname
      || url.pathname !== '/healthz' || url.search || url.hash
    ) return new Response('Not Found', { status: 404 });
    if (request.method !== 'GET') {
      return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET' } });
    }
    try {
      const id = env.SLOT_LEDGER.idFromName('ssai-release-health-controller-v2');
      const response = await env.SLOT_LEDGER.get(id).fetch('https://controller.internal/healthz', {
        method: 'GET',
      });
      logStructured(env, { event: 'health-check', status: response.status });
      return response;
    } catch {
      logStructured(env, { event: 'health-check', status: 503 });
      return noStoreJson(publicHealthBody(env), 503);
    }
  },

  async scheduled(controller, env) {
    if (controller.cron !== '* * * * *' || !Number.isSafeInteger(controller.scheduledTime)) {
      throw new Error('Unexpected controller schedule.');
    }
    const id = env.SLOT_LEDGER.idFromName('ssai-release-health-controller-v2');
    const stub = env.SLOT_LEDGER.get(id);
    const response = await stub.fetch('https://controller.internal/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scheduledTime: controller.scheduledTime, nowMs: Date.now() }),
    });
    const result = await response.json().catch(() => ({ decision: 'failed-closed' }));
    logStructured(env, structuredDecision(result));
    if (!response.ok) throw new Error('Controller evaluation failed closed.');
  },
};

export class ReleaseHealthControllerObject extends ReleaseHealthSlotLedger {
  constructor(state, env) {
    super(state, env);
    this.requestQueue = Promise.resolve();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/healthz' && !url.search && !url.hash) {
      if (request.method !== 'GET') {
        return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET' } });
      }
      try {
        const health = await this.healthStatus(
          runtimeNow(this.env),
          this.env.CONTROLLER_SOURCE_SHA256,
          this.env.CONTROLLER_ACTIVATION_PROFILE_SHA256,
          healthStaleAfterMs(this.env),
        );
        return noStoreJson(publicHealthBody(this.env, health), health.healthy ? 200 : 503);
      } catch {
        return noStoreJson(publicHealthBody(this.env), 503);
      }
    }
    if (url.pathname !== '/evaluate' || url.search || url.hash) return new Response('Not Found', { status: 404 });
    if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
    if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') || '')) {
      return new Response('Unsupported Media Type', { status: 415 });
    }
    const execute = async () => {
      let input;
      try {
        input = await boundedJsonRequest(request);
      } catch {
        return Response.json({ decision: 'invalid-request' }, { status: 400 });
      }
      let result;
      let status = 200;
      try {
        result = await evaluateSlot({
          env: this.env,
          scheduledTime: input.scheduledTime,
          nowMs: input.nowMs,
          ledger: this,
          fetchImpl: this.env.FETCH_IMPL || fetch,
          authProvider: this.env.AUTH_PROVIDER,
          randomUUID: this.env.RANDOM_UUID,
          timeoutSignal: this.env.TIMEOUT_SIGNAL,
          requestOptions: this.env.GITHUB_REQUEST_OPTIONS || {},
        });
      } catch (error) {
        result = boundaryFailureResult(error);
        status = 503;
      }
      try {
        await this.recordCompletedTick({
          scheduledTime: input.scheduledTime,
          completedAt: runtimeNow(this.env),
          sourceDigest: this.env.CONTROLLER_SOURCE_SHA256,
          profileDigest: this.env.CONTROLLER_ACTIVATION_PROFILE_SHA256,
          decision: result.decision,
          failureClass: result.failure_class || null,
        });
      } catch {
        result = {
          decision: 'failed-closed',
          failure_class: 'internal',
          failure_stage: 'failure-record',
        };
        status = 503;
      }
      logStructured(this.env, structuredDecision(result));
      return Response.json(result, { status });
    };
    const pending = this.requestQueue.then(execute, execute);
    this.requestQueue = pending.then(() => undefined, () => undefined);
    return pending;
  }
}
