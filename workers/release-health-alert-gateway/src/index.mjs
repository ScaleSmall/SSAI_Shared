const ALERT_PATH = '/release-health-alert';
const HEALTH_PATH = '/healthz';
const PUBLIC_ORIGIN = 'https://alerts.scalesmall.ai';
const UPSTREAM_URL = 'https://oyyfpkpzalhxztpcdjgq.supabase.co/functions/v1/system-failure-ingest';
const MAX_REQUEST_BYTES = 4_096;
const REQUEST_BODY_TIMEOUT_MS = 2_000;
const MAX_UPSTREAM_RESPONSE_BYTES = 65_536;
const UPSTREAM_TIMEOUT_MS = 10_000;
const RATE_LIMIT_KEY = 'authenticated-release-health-alert-ingest';
const PREVIEW_HEALTH_RATE_LIMIT_KEY = 'immutable-preview-health';
const PREVIEW_HEALTH_HOST_HEADER = 'x-ssai-preview-health-host';
const HEX_64 = /^[a-f0-9]{64}$/;
const VERSION_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const VERSION_TAG = /^[a-f0-9]{40}$/;
const PREVIEW_HEALTH_HOST = /^([a-f0-9]{8})-ssai-release-health-alert-gateway\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$/;

function response(status, body = null, contentType = null) {
  const headers = new Headers({
    'Cache-Control': 'no-store, max-age=0',
    'X-Content-Type-Options': 'nosniff',
  });
  if (contentType !== null) headers.set('Content-Type', contentType);
  return new Response(status === 204 ? null : body, { status, headers });
}

function jsonError(status, code) {
  return response(status, JSON.stringify({ error: code }), 'application/json; charset=utf-8');
}

function parseContentLength(request) {
  const raw = request.headers.get('content-length');
  if (raw === null) return null;
  if (!/^\d+$/.test(raw)) throw new Error('invalid-request');
  const length = Number(raw);
  if (!Number.isSafeInteger(length) || length > MAX_REQUEST_BYTES) throw new Error('request-too-large');
  return length;
}

async function readBoundedBody(request, timeoutMs) {
  parseContentLength(request);
  if (request.body === null) return new Uint8Array();

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      let timer;
      const { done, value } = await Promise.race([
        reader.read(),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('request-timeout')), timeoutMs);
        }),
      ]).finally(() => clearTimeout(timer));
      if (done) break;
      total += value.byteLength;
      if (total > MAX_REQUEST_BYTES) {
        await reader.cancel();
        throw new Error('request-too-large');
      }
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function discardBounded(responseValue) {
  const rawLength = responseValue.headers.get('content-length');
  if (rawLength !== null) {
    if (!/^\d+$/.test(rawLength) || Number(rawLength) > MAX_UPSTREAM_RESPONSE_BYTES) {
      throw new Error('upstream-response-too-large');
    }
  }
  if (responseValue.body === null) return;

  const reader = responseValue.body.getReader();
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_UPSTREAM_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('upstream-response-too-large');
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function validDeliveryHeaders(request) {
  if (request.headers.get('content-type') !== 'application/json') return false;
  const contentEncoding = request.headers.get('content-encoding');
  if (contentEncoding !== null && contentEncoding !== 'identity') return false;
  return HEX_64.test(request.headers.get('x-ssai-alert-id') ?? '')
    && HEX_64.test(request.headers.get('x-ssai-alert-signature') ?? '');
}

function standardBase64(bytes) {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}

function base64Key(value) {
  const text = String(value ?? '');
  if (text.length > 172 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
    throw new Error('invalid-key');
  }
  let bytes;
  try {
    bytes = Uint8Array.from(atob(text), (member) => member.charCodeAt(0));
  } catch {
    throw new Error('invalid-key');
  }
  if (bytes.length < 32 || bytes.length > 128 || standardBase64(bytes) !== text) throw new Error('invalid-key');
  return bytes;
}

async function sha256Hex(value) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))]
    .map((member) => member.toString(16).padStart(2, '0')).join('');
}

function canonicalAlert(body) {
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    throw new Error('invalid-body');
  }
  const keys = ['version', 'slot', 'failure_class', 'status', 'phase', 'decision', 'request_id'];
  const classes = new Set(['provider-evidence', 'transport', 'rate-limit', 'dispatch-unknown', 'circuit-open', 'configuration', 'internal', 'prepared-expired']);
  const phases = new Set(['leased', 'prepared', 'post-attempted', 'unknown', 'confirmed', 'terminal']);
  if (
    !value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== keys.length || !keys.every((key, index) => Object.keys(value)[index] === key)
    || value.version !== 2 || !Number.isSafeInteger(value.slot) || !classes.has(value.failure_class)
    || !(value.status === null || (Number.isSafeInteger(value.status) && value.status >= 0 && value.status <= 599))
    || !phases.has(value.phase) || !/^[a-z][a-z0-9-]{2,47}$/.test(value.decision)
    || !(value.request_id === null || /^[a-f0-9]{32}$/.test(value.request_id))
  ) throw new Error('invalid-body');
  const canonical = JSON.stringify(value);
  if (new TextEncoder().encode(canonical).length !== body.length || new TextDecoder().decode(body) !== canonical) throw new Error('invalid-body');
  return canonical;
}

async function authenticateAlert(body, alertId, signature, keyBase64) {
  const canonical = canonicalAlert(body);
  const expectedId = await sha256Hex(`ssai-release-health-alert-id-v1\0${canonical}`);
  if (expectedId !== alertId) return false;
  let key;
  try {
    key = await crypto.subtle.importKey('raw', base64Key(keyBase64), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  } catch {
    throw new Error('invalid-key');
  }
  const signatureBytes = Uint8Array.from(signature.match(/../g), (member) => Number.parseInt(member, 16));
  return crypto.subtle.verify('HMAC', key, signatureBytes, new TextEncoder().encode(`ssai-release-health-alert-v2\0${alertId}\n${canonical}`));
}

async function forwardAlert(request, { fetchImpl, timeoutMs, bodyTimeoutMs, rateLimiter, hmacKey }) {
  if (!validDeliveryHeaders(request)) return jsonError(400, 'invalid_request');

  let body;
  try {
    body = await readBoundedBody(request, bodyTimeoutMs);
  } catch (error) {
    if (error instanceof Error && error.message === 'request-too-large') return jsonError(413, 'request_too_large');
    if (error instanceof Error && error.message === 'request-timeout') return jsonError(408, 'request_timeout');
    return jsonError(400, 'invalid_request');
  }
  let authenticated;
  try {
    authenticated = await authenticateAlert(
      body,
      request.headers.get('x-ssai-alert-id'),
      request.headers.get('x-ssai-alert-signature'),
      hmacKey,
    );
  } catch (error) {
    return jsonError(error instanceof Error && error.message === 'invalid-key' ? 503 : 400, error instanceof Error && error.message === 'invalid-key' ? 'authentication_unavailable' : 'invalid_request');
  }
  if (!authenticated) return jsonError(401, 'authentication_failed');

  if (!rateLimiter || typeof rateLimiter.limit !== 'function') {
    return jsonError(503, 'rate_limiter_unavailable');
  }
  try {
    const result = await rateLimiter.limit({ key: RATE_LIMIT_KEY });
    if (!result || typeof result.success !== 'boolean') {
      return jsonError(503, 'rate_limiter_unavailable');
    }
    if (!result.success) return jsonError(429, 'rate_limited');
  } catch {
    return jsonError(503, 'rate_limiter_unavailable');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const upstream = await fetchImpl(UPSTREAM_URL, {
      method: 'POST',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'X-SSAI-Alert-Id': request.headers.get('x-ssai-alert-id'),
        'X-SSAI-Alert-Signature': request.headers.get('x-ssai-alert-signature'),
      },
      body,
    });
    await discardBounded(upstream);
    if (upstream.redirected || upstream.status < 200 || upstream.status >= 300) {
      return jsonError(502, 'upstream_unavailable');
    }
    return response(upstream.status);
  } catch {
    return jsonError(controller.signal.aborted ? 504 : 502, controller.signal.aborted ? 'upstream_timeout' : 'upstream_unavailable');
  } finally {
    clearTimeout(timer);
  }
}

async function previewRateLimiterReady(rateLimiter) {
  if (!rateLimiter || typeof rateLimiter.limit !== 'function') return false;
  try {
    const result = await rateLimiter.limit({ key: PREVIEW_HEALTH_RATE_LIMIT_KEY });
    return Boolean(result) && typeof result.success === 'boolean';
  } catch {
    return false;
  }
}

export function createGateway({ fetchImpl = fetch, timeoutMs = UPSTREAM_TIMEOUT_MS, bodyTimeoutMs = REQUEST_BODY_TIMEOUT_MS, rateLimiter = null, hmacKey = null, versionMetadata = null } = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a function.');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > UPSTREAM_TIMEOUT_MS) {
    throw new TypeError('timeoutMs is invalid.');
  }
  if (!Number.isSafeInteger(bodyTimeoutMs) || bodyTimeoutMs < 1 || bodyTimeoutMs > REQUEST_BODY_TIMEOUT_MS) throw new TypeError('bodyTimeoutMs is invalid.');

  return Object.freeze({
    async fetch(request, env = undefined) {
      const url = new URL(request.url);
      if (request.url.includes('?') || url.search !== '') return jsonError(404, 'not_found');

      const productionOrigin = url.origin === PUBLIC_ORIGIN;
      const previewHost = request.headers.get(PREVIEW_HEALTH_HOST_HEADER);
      const previewHostMatch = PREVIEW_HEALTH_HOST.exec(url.hostname);
      const exactPreviewHealth = request.method === 'GET'
        && url.protocol === 'https:'
        && url.port === ''
        && url.username === ''
        && url.password === ''
        && url.pathname === HEALTH_PATH
        && previewHost === url.hostname
        && previewHostMatch !== null;
      if (!productionOrigin && !exactPreviewHealth) return jsonError(404, 'not_found');

      if (url.pathname === HEALTH_PATH) {
        if (request.method !== 'GET') return jsonError(405, 'method_not_allowed');
        const healthRateLimiter = rateLimiter ?? env?.ALERT_INGEST_RATE_LIMITER;
        const rateLimiterReady = Boolean(healthRateLimiter) && typeof healthRateLimiter.limit === 'function';
        const healthVersion = versionMetadata ?? env?.CF_VERSION_METADATA;
        const versionIdReady = Boolean(healthVersion) && VERSION_ID.test(healthVersion.id ?? '');
        const productionVersionReady = versionIdReady && VERSION_TAG.test(healthVersion.tag ?? '');
        const previewMetadataUnavailable = healthVersion === null || healthVersion === undefined;
        const previewVersionReady = previewMetadataUnavailable
          || (versionIdReady && previewHostMatch?.[1] === healthVersion.id.slice(0, 8));
        const previewLimiterReady = exactPreviewHealth
          ? await previewRateLimiterReady(healthRateLimiter)
          : false;
        const healthy = exactPreviewHealth
          ? previewLimiterReady && previewVersionReady
          : rateLimiterReady && productionVersionReady;
        const responseVersionId = exactPreviewHealth
          ? (previewVersionReady && versionIdReady ? healthVersion.id : null)
          : (productionVersionReady ? healthVersion.id : null);
        return response(healthy ? 200 : 503, JSON.stringify({
          schema: 'ssai-release-health-alert-gateway-health-v2',
          component: 'release-health-alert-gateway',
          status: healthy ? 'healthy' : 'unhealthy',
          version_id: responseVersionId,
        }), 'application/json; charset=utf-8');
      }

      if (!productionOrigin) return jsonError(404, 'not_found');
      if (url.pathname !== ALERT_PATH) return jsonError(404, 'not_found');
      if (request.method !== 'POST') return jsonError(405, 'method_not_allowed');
      return forwardAlert(request, {
        fetchImpl,
        timeoutMs,
        bodyTimeoutMs,
        rateLimiter: rateLimiter ?? env?.ALERT_INGEST_RATE_LIMITER,
        hmacKey: hmacKey ?? env?.ALERT_HMAC_KEY,
      });
    },
  });
}

const gateway = createGateway();

export default {
  fetch(request, env) {
    return gateway.fetch(request, env);
  },
};
