import { base64Bytes, hmacHex } from './envelope.mjs';
import { sha256Hex } from './audit.mjs';

const encoder = new TextEncoder();
const classes = new Set([
  'provider-evidence', 'transport', 'rate-limit', 'dispatch-unknown', 'circuit-open',
  'configuration', 'internal', 'prepared-expired',
]);
const phases = new Set(['leased', 'prepared', 'post-attempted', 'unknown', 'confirmed', 'terminal']);

export function sanitizedAlert({ slot, failure_class, status = null, phase, decision, request_id = null }) {
  if (
    !Number.isSafeInteger(slot)
    || !classes.has(failure_class)
    || !phases.has(phase)
    || !/^[a-z][a-z0-9-]{2,47}$/.test(String(decision ?? ''))
    || (request_id !== null && !/^[a-f0-9]{32}$/.test(request_id))
  ) throw new Error('Alert metadata is invalid.');
  return Object.freeze({
    version: 2,
    slot,
    failure_class,
    status: Number.isSafeInteger(status) && status >= 0 && status <= 599 ? status : null,
    phase,
    decision,
    request_id,
  });
}

export async function prepareAlert(payload) {
  const body = JSON.stringify(sanitizedAlert(payload));
  const alert_id = await sha256Hex('ssai-release-health-alert-id-v1', body);
  return Object.freeze({ alert_id, body });
}

async function discardBounded(response, maximum = 65_536) {
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > maximum)) {
    throw new Error('Alert response is oversized.');
  }
  if (!response.body) return;
  const reader = response.body.getReader();
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        throw new Error('Alert response is oversized.');
      }
    }
  } finally {
    reader.releaseLock();
  }
}

export async function deliverSignedAlert(record, {
  sink,
  keyBase64,
  fetchImpl = fetch,
  timeoutSignal = () => AbortSignal.timeout(10_000),
} = {}) {
  if (sink !== 'https://alerts.scalesmall.ai/release-health-alert') {
    throw new Error('Alert sink is not allowlisted.');
  }
  if (
    !record || !/^[a-f0-9]{64}$/.test(String(record.alert_id ?? ''))
    || typeof record.body !== 'string' || record.body.length > 4096
  ) throw new Error('Alert outbox record is invalid.');
  const signature = await hmacHex(
    base64Bytes(keyBase64),
    encoder.encode(`ssai-release-health-alert-v2\0${record.alert_id}\n${record.body}`),
  );
  const response = await fetchImpl(sink, {
    method: 'POST',
    redirect: 'manual',
    signal: timeoutSignal(),
    headers: {
      'Content-Type': 'application/json',
      'X-SSAI-Alert-Id': record.alert_id,
      'X-SSAI-Alert-Signature': signature,
    },
    body: record.body,
  });
  if (response.redirected || response.status < 200 || response.status >= 300) {
    throw Object.assign(new Error('Alert delivery failed.'), { status: response.status });
  }
  await discardBounded(response);
  return Object.freeze({ delivered: true, status: response.status });
}

export async function signedAlert(payload, options) {
  const record = await prepareAlert(payload);
  return deliverSignedAlert(record, options);
}
