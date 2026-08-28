const encoder = new TextEncoder();

export const controllerStateVersion = 'ssai-release-health-controller-state-v2';

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([name, member]) => [name, canonicalValue(member)]),
    );
  }
  return value;
}

export function publicAuditEvent(event) {
  const value = JSON.stringify(canonicalValue(event));
  if (/token|signature|private.?key|hmac|authorization/i.test(value)) {
    throw new Error('Audit event contains prohibited material.');
  }
  return value;
}

export async function sha256Hex(domain, value) {
  const bytes = encoder.encode(`${domain}\0${value}`);
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
    .map((member) => member.toString(16).padStart(2, '0'))
    .join('');
}

export async function chainedAuditHash(previousHash, event) {
  const prior = previousHash || '0'.repeat(64);
  if (!/^[a-f0-9]{64}$/.test(prior)) throw new Error('Audit predecessor is invalid.');
  return sha256Hex(
    'ssai-release-health-controller-audit-v1',
    `${prior}\n${publicAuditEvent(event)}`,
  );
}

export async function activationProof(sourceDigest, profileDigest, observations) {
  if (!/^[a-f0-9]{64}$/.test(sourceDigest) || !/^[a-f0-9]{64}$/.test(profileDigest)) {
    throw new Error('Activation digest is invalid.');
  }
  if (
    !Array.isArray(observations)
    || observations.length !== 2
    || observations[1].slot !== observations[0].slot + 15
    || observations.some(({ slot, audit_hash }) => (
      !Number.isSafeInteger(slot) || !/^[a-f0-9]{64}$/.test(audit_hash)
    ))
  ) {
    throw new Error('Activation observations are invalid.');
  }
  return sha256Hex(
    'ssai-release-health-controller-activation-v1',
    publicAuditEvent({ observations, profile_digest: profileDigest, source_digest: sourceDigest }),
  );
}
