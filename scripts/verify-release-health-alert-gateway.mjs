import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createGateway as createGatewayImplementation } from '../workers/release-health-alert-gateway/src/index.mjs';

const endpoint = 'https://alerts.scalesmall.ai/release-health-alert';
const hmacKeyBytes = Buffer.alloc(32, 7);
const hmacKey = hmacKeyBytes.toString('base64');
const canonicalBody = JSON.stringify({ version: 2, slot: 123, failure_class: 'transport', status: null, phase: 'terminal', decision: 'delivery-failed', request_id: null });
const id = createHash('sha256').update(`ssai-release-health-alert-id-v1\0${canonicalBody}`).digest('hex');
const signature = createHmac('sha256', hmacKeyBytes).update(`ssai-release-health-alert-v2\0${id}\n${canonicalBody}`).digest('hex');
const allowRateLimiter = Object.freeze({
  async limit({ key }) {
    assert.equal(key, 'authenticated-release-health-alert-ingest');
    return { success: true };
  },
});
const createGateway = (options = {}) => createGatewayImplementation({ rateLimiter: allowRateLimiter, hmacKey, ...options });

async function deliveryRequest(body = canonicalBody, overrides = {}) {
  const id = overrides.id ?? createHash('sha256').update(`ssai-release-health-alert-id-v1\0${body}`).digest('hex');
  const signature = overrides.signature ?? createHmac('sha256', hmacKeyBytes).update(`ssai-release-health-alert-v2\0${id}\n${body}`).digest('hex');
  return new Request(overrides.url ?? endpoint, {
    method: overrides.method ?? 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-SSAI-Alert-Id': id,
      'X-SSAI-Alert-Signature': signature,
      Authorization: 'must-not-forward',
      Cookie: 'must-not-forward',
      'X-Forwarded-For': 'must-not-forward',
      ...overrides.headers,
    },
    body: overrides.method === 'GET' ? undefined : body,
  });
}

{
  let quotaCalls = 0;
  let upstreamCalls = 0;
  const gateway = createGatewayImplementation({
    hmacKey,
    rateLimiter: { async limit() { quotaCalls += 1; return { success: true }; } },
    fetchImpl: async () => { upstreamCalls += 1; return upstream(202); },
  });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const fake = await gateway.fetch(await deliveryRequest(canonicalBody, { signature: 'b'.repeat(64) }));
    assert.equal(fake.status, 401);
  }
  assert.equal(quotaCalls, 0, 'unauthenticated headers must not consume authenticated quota');
  assert.equal(upstreamCalls, 0);
  assert.equal((await gateway.fetch(await deliveryRequest())).status, 202);
  assert.equal(quotaCalls, 1);
  assert.equal(upstreamCalls, 1);

  const missingKey = createGatewayImplementation({
    rateLimiter: { async limit() { quotaCalls += 1; return { success: true }; } },
    fetchImpl: async () => { upstreamCalls += 1; return upstream(202); },
  });
  assert.equal((await missingKey.fetch(await deliveryRequest())).status, 503);
  assert.equal(quotaCalls, 1);
  assert.equal(upstreamCalls, 1);

  const tampered = `${canonicalBody} `;
  assert.equal((await gateway.fetch(await deliveryRequest(tampered))).status, 400);
  const noncanonical = JSON.stringify({ slot: 123, version: 2, failure_class: 'transport', status: null, phase: 'terminal', decision: 'delivery-failed', request_id: null });
  assert.equal((await gateway.fetch(await deliveryRequest(noncanonical))).status, 400);
  assert.equal(quotaCalls, 1);
  assert.equal(upstreamCalls, 1);
}

{
  let cancelled = false;
  let quotaCalls = 0;
  const body = new ReadableStream({ cancel() { cancelled = true; } });
  const request = new Request(endpoint, {
    method: 'POST', body, duplex: 'half',
    headers: { 'Content-Type': 'application/json', 'X-SSAI-Alert-Id': id, 'X-SSAI-Alert-Signature': signature },
  });
  const gateway = createGatewayImplementation({
    hmacKey, bodyTimeoutMs: 5,
    rateLimiter: { async limit() { quotaCalls += 1; return { success: true }; } },
  });
  const result = await gateway.fetch(request);
  assert.equal(result.status, 408);
  assert.equal(quotaCalls, 0);
  assert.equal(cancelled, true);
}

function upstream(status = 202, body = '') {
  return new Response(status === 204 ? null : body, { status });
}

{
  const calls = [];
  const gateway = createGateway({
    async fetchImpl(url, options) {
      calls.push({ url, options });
      return upstream(202, 'accepted');
    },
  });
  const raw = canonicalBody;
  const result = await gateway.fetch(await deliveryRequest(raw));
  assert.equal(result.status, 202);
  assert.equal(await result.text(), '');
  assert.match(result.headers.get('cache-control'), /no-store/);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://oyyfpkpzalhxztpcdjgq.supabase.co/functions/v1/system-failure-ingest');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.redirect, 'error');
  assert.ok(calls[0].options.signal instanceof AbortSignal);
  assert.equal(new TextDecoder().decode(calls[0].options.body), raw);
  const headers = new Headers(calls[0].options.headers);
  assert.deepEqual([...headers.keys()].sort(), ['content-type', 'x-ssai-alert-id', 'x-ssai-alert-signature']);
  assert.equal(headers.get('content-type'), 'application/json');
  assert.equal(headers.get('x-ssai-alert-id'), id);
  assert.equal(headers.get('x-ssai-alert-signature'), signature);
}

{
  let forwarded = false;
  const missingHealth = await createGatewayImplementation().fetch(
    new Request('https://alerts.scalesmall.ai/healthz'),
  );
  assert.equal(missingHealth.status, 503);
  assert.deepEqual(await missingHealth.json(), {
    schema: 'ssai-release-health-alert-gateway-health-v1',
    component: 'release-health-alert-gateway',
    status: 'unhealthy',
  });

  const denied = createGatewayImplementation({ hmacKey,
    fetchImpl: async () => { forwarded = true; return upstream(); },
    rateLimiter: { limit: async () => ({ success: false }) },
  });
  const deniedResult = await denied.fetch(await deliveryRequest());
  assert.equal(deniedResult.status, 429);
  assert.deepEqual(await deniedResult.json(), { error: 'rate_limited' });
  assert.equal(forwarded, false);

  const unavailable = createGatewayImplementation({ hmacKey,
    fetchImpl: async () => { forwarded = true; return upstream(); },
    rateLimiter: { limit: async () => { throw new Error('unavailable'); } },
  });
  const unavailableResult = await unavailable.fetch(await deliveryRequest());
  assert.equal(unavailableResult.status, 503);
  assert.deepEqual(await unavailableResult.json(), { error: 'rate_limiter_unavailable' });
  assert.equal(forwarded, false);
}

for (const status of [200, 202, 204, 208, 226]) {
  const gateway = createGateway({ fetchImpl: async () => upstream(status) });
  const result = await gateway.fetch(await deliveryRequest());
  assert.equal(result.status, status);
  assert.equal(await result.text(), '');
}

{
  let called = false;
  const gateway = createGateway({ fetchImpl: async () => { called = true; return upstream(); } });
  const health = await gateway.fetch(new Request('https://alerts.scalesmall.ai/healthz'));
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), {
    schema: 'ssai-release-health-alert-gateway-health-v1',
    component: 'release-health-alert-gateway',
    status: 'healthy',
  });
  assert.match(health.headers.get('cache-control'), /no-store/);
  assert.equal(health.headers.get('location'), null);
  assert.equal(health.redirected, false);

  const previewHost = 'c-0123456789ab-ssai-release-health-alert-gateway.ssai-preview.workers.dev';
  const previewHealth = await gateway.fetch(new Request(`https://${previewHost}/healthz`, {
    headers: { 'X-SSAI-Preview-Health-Host': previewHost },
  }));
  assert.equal(previewHealth.status, 200);
  assert.deepEqual(await previewHealth.json(), {
    schema: 'ssai-release-health-alert-gateway-health-v1',
    component: 'release-health-alert-gateway',
    status: 'healthy',
  });
  assert.equal(previewHealth.headers.get('location'), null);
  assert.equal(previewHealth.redirected, false);

  for (const request of [
    new Request(`https://${previewHost}/healthz`),
    new Request(`https://${previewHost}/healthz`, {
      headers: { 'X-SSAI-Preview-Health-Host': 'c-fedcba987654-ssai-release-health-alert-gateway.ssai-preview.workers.dev' },
    }),
    new Request('https://arbitrary.workers.dev/healthz', {
      headers: { 'X-SSAI-Preview-Health-Host': 'arbitrary.workers.dev' },
    }),
    new Request('https://c-0123456789ab-ssai-release-health-alert-gateway.other.example/healthz', {
      headers: { 'X-SSAI-Preview-Health-Host': 'c-0123456789ab-ssai-release-health-alert-gateway.other.example' },
    }),
  ]) {
    const rejectedPreview = await gateway.fetch(request);
    assert.equal(rejectedPreview.status, 404);
    assert.equal(rejectedPreview.headers.get('location'), null);
    assert.equal(rejectedPreview.redirected, false);
  }

  const previewPost = await gateway.fetch(await deliveryRequest(canonicalBody, {
    url: `https://${previewHost}/release-health-alert`,
    headers: { 'X-SSAI-Preview-Health-Host': previewHost },
  }));
  assert.equal(previewPost.status, 404);
  assert.equal(previewPost.headers.get('location'), null);
  assert.equal(previewPost.redirected, false);

  const rejected = [
    new Request('https://alerts.scalesmall.ai/healthz?probe=1'),
    new Request('https://alerts.scalesmall.ai/healthz?'),
    new Request('https://alerts.scalesmall.ai/unknown'),
    new Request('https://other.example/healthz'),
    await deliveryRequest(canonicalBody, { url: 'https://other.example/release-health-alert' }),
    await deliveryRequest(canonicalBody, { url: `${endpoint}?retry=1` }),
    await deliveryRequest(canonicalBody, { url: `${endpoint}?` }),
    await deliveryRequest(canonicalBody, { method: 'PUT' }),
  ];
  for (const request of rejected) {
    const result = await gateway.fetch(request);
    assert.ok(result.status === 404 || result.status === 405);
    assert.match(result.headers.get('cache-control'), /no-store/);
  }
  assert.equal(called, false);
}

{
  let called = false;
  const gateway = createGateway({ fetchImpl: async () => { called = true; return upstream(); } });
  const badHeaders = [
    { 'Content-Type': 'application/json; charset=utf-8' },
    { 'Content-Type': 'text/plain' },
    { 'X-SSAI-Alert-Id': 'A'.repeat(64) },
    { 'X-SSAI-Alert-Id': 'a'.repeat(63) },
    { 'X-SSAI-Alert-Signature': 'g'.repeat(64) },
    { 'Content-Encoding': 'gzip' },
  ];
  for (const headers of badHeaders) {
    const result = await gateway.fetch(await deliveryRequest(canonicalBody, { headers }));
    assert.equal(result.status, 400);
  }
  assert.equal(called, false);
}

{
  let calls = 0;
  const gateway = createGateway({ fetchImpl: async () => { calls += 1; return upstream(); } });
  const exact = await gateway.fetch(await deliveryRequest(canonicalBody));
  assert.equal(exact.status, 202);
  const oversized = await gateway.fetch(await deliveryRequest('x'.repeat(4_097)));
  assert.equal(oversized.status, 413);
  const declaredOversized = await gateway.fetch(await deliveryRequest('', { headers: { 'Content-Length': '4097' } }));
  assert.equal(declaredOversized.status, 413);
  assert.equal(calls, 1);
}

{
  let cancelled = false;
  let called = false;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(3_000));
      controller.enqueue(new Uint8Array(1_097));
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-SSAI-Alert-Id': id,
      'X-SSAI-Alert-Signature': signature,
    },
    body,
    duplex: 'half',
  });
  const gateway = createGateway({ fetchImpl: async () => { called = true; return upstream(); } });
  const result = await gateway.fetch(request);
  assert.equal(result.status, 413);
  assert.equal(cancelled, true);
  assert.equal(called, false);
}

{
  const gateway = createGateway({
    timeoutMs: 10,
    fetchImpl: async (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    }),
  });
  const result = await gateway.fetch(await deliveryRequest());
  assert.equal(result.status, 504);
  assert.deepEqual(await result.json(), { error: 'upstream_timeout' });
}

for (const resultFactory of [
  async () => upstream(302, 'redirect'),
  async () => upstream(500, 'private upstream detail'),
  async () => { throw new Error('private network detail'); },
  async () => upstream(200, 'x'.repeat(65_537)),
]) {
  const gateway = createGateway({ fetchImpl: resultFactory });
  const result = await gateway.fetch(await deliveryRequest());
  assert.equal(result.status, 502);
  assert.deepEqual(await result.json(), { error: 'upstream_unavailable' });
}

assert.throws(() => createGateway({ fetchImpl: null }), /fetchImpl/);
assert.throws(() => createGateway({ timeoutMs: 0 }), /timeoutMs/);
assert.throws(() => createGateway({ timeoutMs: 10_001 }), /timeoutMs/);

const source = await readFile(new URL('../workers/release-health-alert-gateway/src/index.mjs', import.meta.url), 'utf8');
assert.doesNotMatch(source, /from ['"](?!\.\/|node:)/);
assert.doesNotMatch(source, /console\.|Authorization|Cookie|SUPABASE_SERVICE_ROLE_KEY/);

const wrangler = JSON.parse((await readFile(new URL('../workers/release-health-alert-gateway/wrangler.jsonc', import.meta.url), 'utf8')).replace(/^\s*\/\/.*$/gm, ''));
assert.equal(wrangler.workers_dev, false);
assert.equal(wrangler.preview_urls, true);
assert.equal(wrangler.routes.length, 1);
assert.deepEqual(wrangler.routes[0], { pattern: 'alerts.scalesmall.ai', custom_domain: true });
assert.deepEqual(wrangler.ratelimits, [{
  name: 'ALERT_INGEST_RATE_LIMITER',
  namespace_id: '735104001',
  simple: { limit: 60, period: 60 },
}]);
assert.equal(wrangler.observability.enabled, true);
assert.equal(wrangler.observability.logs.enabled, true);
assert.equal(wrangler.observability.logs.invocation_logs, true);
assert.equal('vars' in wrangler, false);

console.log('Release health alert gateway contract verified.');
