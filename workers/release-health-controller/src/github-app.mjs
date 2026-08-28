import { createInstallationAccessToken, githubApi } from './github-api.mjs';

const encoder = new TextEncoder();
const readCache = new Map();

function base64Url(value) {
  let text = '';
  for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
  return btoa(text).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export async function githubAppJwt(clientId, pem, now = Math.floor(Date.now() / 1000)) {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(String(clientId ?? '')) || !Number.isSafeInteger(now)) {
    throw new Error('GitHub App identity is invalid.');
  }
  const keyLabel = ['PRIVATE', 'KEY'].join(' ');
  const beginMarker = `-----BEGIN ${keyLabel}-----`;
  const endMarker = `-----END ${keyLabel}-----`;
  const match = new RegExp(`^${beginMarker}\\s+([A-Za-z0-9+/=\\s]+)\\s+${endMarker}\\s*$`)
    .exec(String(pem ?? ''));
  if (!match) throw new Error('GitHub App private key is invalid.');
  let raw;
  try {
    raw = Uint8Array.from(atob(match[1].replace(/\s/g, '')), (member) => member.charCodeAt(0));
  } catch {
    throw new Error('GitHub App private key is invalid.');
  }
  const key = await crypto.subtle.importKey(
    'pkcs8', raw, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'],
  );
  const header = base64Url(encoder.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const payload = base64Url(encoder.encode(JSON.stringify({ iat: now - 60, exp: now + 540, iss: String(clientId) })));
  const data = `${header}.${payload}`;
  const signature = base64Url(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(data)));
  return `${data}.${signature}`;
}

export async function installationToken(
  fetchImpl,
  env,
  now = Math.floor(Date.now() / 1000),
  permissionMode = 'read',
  requestOptions = {},
) {
  if (!['read', 'write'].includes(permissionMode) || !Number.isSafeInteger(now)) {
    throw new Error('Installation token permission mode is invalid.');
  }
  if (env.GITHUB_APP_CREDENTIAL_EPOCH !== 'github-app-credential-v1') {
    throw new Error('GitHub App credential epoch is invalid.');
  }
  const cacheKey = [env.GITHUB_INSTALLATION_ID, env.GITHUB_APP_CLIENT_ID, env.GITHUB_APP_CREDENTIAL_EPOCH].join(':');
  const cached = readCache.get(cacheKey);
  if (permissionMode === 'read' && cached && cached.expiresAt - now >= 300) return cached;
  const jwt = await githubAppJwt(env.GITHUB_APP_CLIENT_ID, env.GITHUB_APP_PRIVATE_KEY, now);
  const value = await createInstallationAccessToken(
    fetchImpl,
    env.GITHUB_INSTALLATION_ID,
    jwt,
    permissionMode,
    requestOptions,
  );
  if (value.expiresAt < now + 300 || value.expiresAt > now + 3_700) {
    throw new Error('Installation token expiry is invalid.');
  }
  if (permissionMode === 'read') readCache.set(cacheKey, value);
  return value;
}

export function clearInstallationTokenCacheForTest() {
  readCache.clear();
}

export { githubApi } from './github-api.mjs';
