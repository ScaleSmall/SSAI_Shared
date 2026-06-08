const DEFAULT_LDP_TIMEOUT_MS = 10000;
const MAX_LDP_RESPONSE_BYTES = 256 * 1024;

export const LDP_EF_BASE = getPublicEnv('VITE_LDP_API_URL') || 'https://oyyfpkpzalhxztpcdjgq.supabase.co/functions/v1/ldp-api';

function getPublicEnv(name) {
  return typeof import.meta !== 'undefined' ? import.meta.env?.[name] || '' : '';
}

function normalizeLdpPath(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
    throw new Error('LDP path must be a relative path starting with /');
  }
  return path;
}

function safeErrorMessage(error) {
  const raw = error instanceof Error ? error.message : String(error || 'Unknown error');
  return raw
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]')
    .replace(/\b(token|api[_-]?key|apikey|password|secret|authorization)\s*[=:]?\s*[A-Za-z0-9._~+/=-]+/gi, '$1 [redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[redacted-jwt]')
    .slice(0, 500);
}

async function readJsonWithLimit(response) {
  const text = await readTextWithLimit(response);
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: 'Invalid JSON response' };
  }
}

async function readTextWithLimit(response) {
  if (!response.body?.getReader) {
    const text = await response.text();
    return text.slice(0, MAX_LDP_RESPONSE_BYTES);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_LDP_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('Response body too large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock?.();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export function createLdpApi(supabase) {
  async function getLdpKey() {
    const { data } = await supabase.from('system_settings')
      .select('setting_value_json')
      .eq('setting_key', 'ldp_config')
      .single();
    return data?.setting_value_json?.api_key || getPublicEnv('VITE_LDP_API_KEY') || '';
  }

  async function ldpFetch(path, method = 'GET', body = null) {
    const normalizedPath = normalizeLdpPath(path);
    const key = await getLdpKey();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DEFAULT_LDP_TIMEOUT_MS);

    try {
      const opts = {
        method,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'X-LDP-API-Key': key,
        },
      };
      if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
      const res = await fetch(`${LDP_EF_BASE}${normalizedPath}`, opts);
      if (!res.ok) {
        const err = await readJsonWithLimit(res).catch((error) => ({ error: safeErrorMessage(error) }));
        throw new Error(err.error || `LDP API error: ${res.status}`);
      }
      return readJsonWithLimit(res);
    } catch (error) {
      throw new Error(safeErrorMessage(error));
    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    getHealth: (entityId) => ldpFetch(`/api/v1/locations/${encodeURIComponent(entityId)}/health`),
    getCorrection: (correctionId) => ldpFetch(`/api/v1/corrections/${encodeURIComponent(correctionId)}`),
    syncLocation: (entityId, canonical) => ldpFetch('/api/v1/locations/sync', 'POST', { entity_id: entityId, canonical }),
    setSuppressedAddress: (entityId, address) => ldpFetch(`/api/v1/locations/${encodeURIComponent(entityId)}/suppressed-address`, 'POST', address),
  };
}
