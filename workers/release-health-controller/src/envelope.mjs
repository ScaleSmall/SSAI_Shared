export const unsignedFields = Object.freeze([
  'version', 'repository', 'repository_id', 'workflow_id', 'workflow_path', 'ref',
  'expected_sha', 'slot_epoch_minute', 'request_id', 'issued_at_epoch_second',
  'expires_at_epoch_second',
]);

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const prefix = encoder.encode('ssai-release-health-fallback-envelope-v1\0');

function u32(number) {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, number);
  return result;
}

function concat(parts) {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function standardBase64(bytes) {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}

function rawBase64Url(bytes) {
  return standardBase64(bytes).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function exactDecimal(value, label) {
  const text = String(value ?? '');
  if (!/^(?:0|[1-9][0-9]{0,11})$/.test(text)) throw new Error(`${label} is invalid.`);
  const number = Number(text);
  if (!Number.isSafeInteger(number)) throw new Error(`${label} is invalid.`);
  return number;
}

export function validateEnvelope(input) {
  if (
    !input || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).length !== unsignedFields.length
    || !unsignedFields.every((name) => Object.hasOwn(input, name))
  ) throw new Error('Fallback envelope field set is invalid.');
  for (const name of unsignedFields) {
    const value = String(input[name]);
    if (!value || value.trim() !== value || value.includes('\0') || encoder.encode(value).length > 512) {
      throw new Error('Fallback envelope value is invalid.');
    }
  }
  if (
    input.version !== 'ssai-release-health-fallback-v1'
    || input.repository !== 'ScaleSmall/SSAI_Shared'
    || input.repository_id !== '1183552904'
    || input.workflow_id !== '344170407'
    || input.workflow_path !== '.github/workflows/release-health-monitor-fallback.yml'
    || input.ref !== 'refs/heads/main'
    || !/^[a-f0-9]{40}$/.test(input.expected_sha)
    || !/^[a-f0-9]{32}$/.test(input.request_id)
  ) throw new Error('Fallback envelope boundary is invalid.');
  const slot = exactDecimal(input.slot_epoch_minute, 'slot_epoch_minute');
  const issued = exactDecimal(input.issued_at_epoch_second, 'issued_at_epoch_second');
  const expires = exactDecimal(input.expires_at_epoch_second, 'expires_at_epoch_second');
  if (
    ![1, 16, 31, 46].includes(new Date(slot * 60_000).getUTCMinutes())
    || issued < slot * 60 + 600 || issued >= slot * 60 + 900
    || expires <= issued || expires > issued + 300
  ) throw new Error('Fallback envelope time relation is invalid.');
  return input;
}

export function canonicalEnvelope(input) {
  validateEnvelope(input);
  const parts = [prefix];
  for (const name of unsignedFields) {
    const encodedName = encoder.encode(name);
    const encodedValue = encoder.encode(String(input[name]));
    parts.push(u32(encodedName.length), encodedName, u32(encodedValue.length), encodedValue);
  }
  return concat(parts);
}

export function encodeEnvelope(input) {
  return rawBase64Url(canonicalEnvelope(input));
}

export function parseEnvelope(value) {
  const text = String(value ?? '');
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length > 8192) {
    throw new Error('Fallback envelope encoding is invalid.');
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4);
  let bytes;
  try {
    bytes = Uint8Array.from(atob(padded), (member) => member.charCodeAt(0));
  } catch {
    throw new Error('Fallback envelope encoding is invalid.');
  }
  if (rawBase64Url(bytes) !== text || bytes.length < prefix.length) {
    throw new Error('Fallback envelope encoding is noncanonical.');
  }
  for (let index = 0; index < prefix.length; index += 1) {
    if (bytes[index] !== prefix[index]) throw new Error('Fallback envelope prefix is invalid.');
  }
  const result = {};
  let offset = prefix.length;
  for (const expectedName of unsignedFields) {
    if (offset + 4 > bytes.length) throw new Error('Fallback envelope is truncated.');
    const nameLength = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0);
    offset += 4;
    if (nameLength < 1 || offset + nameLength + 4 > bytes.length) {
      throw new Error('Fallback envelope field is malformed.');
    }
    const name = decoder.decode(bytes.subarray(offset, offset + nameLength));
    offset += nameLength;
    const valueLength = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0);
    offset += 4;
    if (name !== expectedName || offset + valueLength > bytes.length) {
      throw new Error('Fallback envelope field order is invalid.');
    }
    result[name] = decoder.decode(bytes.subarray(offset, offset + valueLength));
    offset += valueLength;
  }
  if (offset !== bytes.length || encodeEnvelope(result) !== text) {
    throw new Error('Fallback envelope has extra or noncanonical bytes.');
  }
  return Object.freeze(result);
}

export async function hmacHex(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC', key, data))]
    .map((member) => member.toString(16).padStart(2, '0')).join('');
}

export function base64Bytes(value) {
  const text = String(value ?? '');
  if (
    text.length > 172
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)
  ) throw new Error('Admission HMAC key is invalid.');
  let bytes;
  try {
    bytes = Uint8Array.from(atob(text), (member) => member.charCodeAt(0));
  } catch {
    throw new Error('Admission HMAC key is invalid.');
  }
  if (bytes.length < 32 || bytes.length > 128 || standardBase64(bytes) !== text) {
    throw new Error('Admission HMAC key is invalid.');
  }
  return bytes;
}

export async function signEnvelope(input, keyBase64) {
  return hmacHex(base64Bytes(keyBase64), canonicalEnvelope(input));
}
