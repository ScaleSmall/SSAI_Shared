const DEFAULT_TIMEOUT_MS = 10000;
const MAX_RESPONSE_BYTES = 256 * 1024;

export const API_BASE = getPublicEnv('VITE_API_BASE_URL') || '';

function getPublicEnv(name) {
  return typeof import.meta !== 'undefined' ? import.meta.env?.[name] || '' : '';
}

function normalizePath(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
    throw new Error('API path must be a relative path starting with /');
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
    return text.slice(0, MAX_RESPONSE_BYTES);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('Response body too large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock?.();
  }

  return new TextDecoder().decode(concatChunks(chunks, total));
}

function concatChunks(chunks, total) {
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function getAuthHeaders(supabase) {
  const { data: { session } = {} } = await supabase.auth.getSession();
  const headers = { 'Content-Type': 'application/json' };
  if (session?.access_token) headers.Authorization = `Bearer ${session.access_token}`;
  return headers;
}

async function request(supabase, method, path, body) {
  const normalizedPath = normalizePath(path);
  const headers = await getAuthHeaders(supabase);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const opts = { method, headers, signal: controller.signal };
    if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
    const res = await fetch(`${API_BASE}${normalizedPath}`, opts);
    if (!res.ok) {
      const err = await readJsonWithLimit(res).catch((error) => ({ error: safeErrorMessage(error) }));
      throw new Error(err.error || `Request failed: ${res.status}`);
    }
    return readJsonWithLimit(res);
  } catch (error) {
    throw new Error(safeErrorMessage(error));
  } finally {
    clearTimeout(timeout);
  }
}

export function createAuthenticatedApi(supabase) {
  return {
    get: (path) => request(supabase, 'GET', path),
    post: (path, body) => request(supabase, 'POST', path, body),
    patch: (path, body) => request(supabase, 'PATCH', path, body),
  };
}
