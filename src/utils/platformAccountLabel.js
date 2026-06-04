export function cleanDisplayText(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

export function isRawPlatformIdentifier(value) {
  const text = cleanDisplayText(value);
  if (!text) return false;
  const lower = text.toLowerCase();
  return (
    lower.startsWith('urn:') ||
    lower.includes('/locations/') ||
    lower.includes('/accounts/') ||
    /^[0-9]{6,}$/.test(text) ||
    /^UC[A-Za-z0-9_-]{10,}$/.test(text)
  );
}

export function formatHandle(value) {
  const text = cleanDisplayText(value);
  if (!text || isRawPlatformIdentifier(text)) return null;
  const withoutAt = text.startsWith('@') ? text.slice(1) : text;
  if (!withoutAt || /\s/.test(withoutAt)) return null;
  return `@${withoutAt}`;
}

export function firstSafeText(...values) {
  for (const value of values) {
    const text = cleanDisplayText(value);
    if (text && !isRawPlatformIdentifier(text)) return text;
  }
  return null;
}

export function currentLinkedInOrgName(details) {
  const orgUrn = cleanDisplayText(details?.org_urn);
  const orgs = Array.isArray(details?.available_orgs) ? details.available_orgs : [];
  const current = orgs.find(org => org?.urn === orgUrn) || null;
  return firstSafeText(
    current?.name,
    current?.display_name,
    current?.localizedName,
    current?.localized_name,
    current?.['organization~']?.localizedName,
  );
}

export function formatPlatformAccountLabel(platform, details = {}) {
  switch (platform) {
    case 'facebook':
      return firstSafeText(details.page_name, details.name) || formatHandle(details.page_username || details.handle || details.ig_username);
    case 'instagram':
      return formatHandle(details.username || details.ig_username || details.handle);
    case 'x':
      return formatHandle(details.username || details.handle);
    case 'tiktok':
      return formatHandle(details.username || details.handle) || firstSafeText(details.display_name);
    case 'linkedin':
      return currentLinkedInOrgName(details);
    case 'youtube':
      return formatHandle(details.handle) || firstSafeText(details.channel_title, details.channel_name);
    case 'gbp':
      return firstSafeText(details.location_name, details.account_name, details.location);
    case 'website':
      return firstSafeText(details.domain);
    default:
      return null;
  }
}
