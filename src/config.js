// Single source of truth for platform and connector metadata.
export const PLATFORM_ORDER = [
  'facebook', 'instagram', 'x', 'youtube', 'linkedin', 'gbp', 'tiktok', 'website',
];

export const PLATFORM_META = {
  facebook:  { name: 'Facebook',        icon: 'f',  color: '#1877f2', note: 'Page posting + connects Instagram' },
  instagram: { name: 'Instagram',       icon: '📷', color: '#e1306c', note: 'Connected through Facebook', noOAuth: true, derived: true },
  x:         { name: 'X / Twitter',     icon: '𝕏',  color: '#000000', note: 'Auto-refreshing 2-hour tokens' },
  youtube:   { name: 'YouTube',         icon: '▶',  color: '#ff0000', note: 'YouTube Shorts from job photos' },
  linkedin:  { name: 'LinkedIn',        icon: 'in', color: '#0a66c2', note: 'Company page posting' },
  gbp:       { name: 'Google Business', icon: 'G',  color: '#34a853', note: 'Local posts + photo gallery' },
  tiktok:    { name: 'TikTok',          icon: '♪',  color: '#010101', note: 'Short-form video posting' },
  website:   { name: 'Website Gallery', icon: '🌐', color: '#6366f1', note: 'Auto-publish job photos to your site', noOAuth: true },
  reddit:    { name: 'Reddit',          icon: 'R',  color: '#ff4500', hidden: true },
};

export const CONNECTOR_ICONS = {
  companycam:    '📸',
  manual_upload: '⬆️',
  google_drive:  '📁',
  dropbox:       '💧',
  onedrive:      '☁️',
  box:           '📦',
  jobber:        '🔧',
  jobnimbus:     '🏚️',
  workiz:        '⚡',
  housecall_pro: '🏠',
  servicetitan:  '🔩',
  procore:       '🏗️',
  acculynx:      '🏘️',
  buildertrend:  '🏗️',
  houzz_pro:     '🪴',
};

export function buildConnectUrls(supabaseUrl) {
  return {
    oauthStatusUrl:    `${supabaseUrl}/functions/v1/oauth-status`,
    connectorStatusUrl:`${supabaseUrl}/functions/v1/connect-connector`,
  };
}