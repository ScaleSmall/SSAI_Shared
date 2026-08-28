import { evaluateSlot } from './controller.mjs';
import { ReleaseHealthSlotLedger } from './store.mjs';

export { ReleaseHealthSlotLedger };

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
  const decision = /^[a-z][a-z0-9-]{2,47}$/.test(String(result?.decision ?? ''))
    ? result.decision
    : 'failed-closed';
  const activationProof = /^[a-f0-9]{64}$/.test(String(result?.activation_proof ?? ''))
    ? result.activation_proof
    : null;
  return Object.freeze({
    component: 'release-health-controller',
    decision,
    activation_proof: activationProof,
  });
}

export default {
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
    (env.STRUCTURED_LOG || console.log)(JSON.stringify(structuredDecision(result)));
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
      try {
        const result = await evaluateSlot({
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
        (this.env.STRUCTURED_LOG || console.log)(JSON.stringify(structuredDecision(result)));
        return Response.json(result);
      } catch (error) {
        const result = error.result || { decision: 'failed-closed', failure_class: 'internal' };
        (this.env.STRUCTURED_LOG || console.log)(JSON.stringify(structuredDecision(result)));
        return Response.json(result, { status: 503 });
      }
    };
    const pending = this.requestQueue.then(execute, execute);
    this.requestQueue = pending.then(() => undefined, () => undefined);
    return pending;
  }
}
