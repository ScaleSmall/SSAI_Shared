export function latestByIdentity(records, identityOf) {
  if (!Array.isArray(records)) throw new TypeError('records must be an array');
  if (typeof identityOf !== 'function') throw new TypeError('identityOf must be a function');

  const latest = new Map();
  for (const record of records) {
    const identity = String(identityOf(record) || '').trim();
    if (!identity) throw new Error('release-health record identity must not be empty');
    const current = latest.get(identity);
    if (!current || compareOccurrence(record, current) > 0) latest.set(identity, record);
  }
  return [...latest.values()];
}

function compareOccurrence(left, right) {
  const timeDifference = occurrenceTime(left) - occurrenceTime(right);
  if (timeDifference !== 0) return timeDifference;
  return numericId(left?.id) - numericId(right?.id);
}

function occurrenceTime(record) {
  const timestamp = record?.started_at || record?.created_at || record?.updated_at || record?.completed_at;
  const parsed = Date.parse(String(timestamp || ''));
  return Number.isFinite(parsed) ? parsed : 0;
}

function numericId(value) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : 0;
}
