#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import {
  formatPlatformAccountLabel,
  isRawPlatformIdentifier,
} from '../src/utils/platformAccountLabel.js';

async function load(path) {
  return readFile(path, 'utf8');
}

function includesAll(source, needles, label) {
  for (const needle of needles) {
    assert(source.includes(needle), `${label} missing "${needle}"`);
  }
}

function excludesAll(source, needles, label) {
  for (const needle of needles) {
    assert(!source.includes(needle), `${label} should not include "${needle}"`);
  }
}

function appearsInOrder(source, needles, label) {
  let offset = -1;
  for (const needle of needles) {
    const nextOffset = source.indexOf(needle);
    assert(nextOffset !== -1, `${label} missing "${needle}"`);
    assert(nextOffset > offset, `${label} expected "${needle}" after previous item`);
    offset = nextOffset;
  }
}

const panel = await load('src/components/ConnectPanel.jsx');
const hook = await load('src/hooks/useConnect.js');
const styles = await load('src/connect.css');
const accountLabel = await load('src/utils/platformAccountLabel.js');

includesAll(panel, [
  "new Set(['hubspot', 'gohighlevel', 'salesforce'])",
  'API Posting Proxy',
  'Photo Feed Sources',
  'Customer Data Sources',
  'format: \'json\'',
  'return_to: `${window.location.origin}/oauth-complete`',
  'Authorization: `Bearer ${token}`',
  'onStartOAuth(c.connector_type)',
  'Connect ${c.display_name}',
  'allowPublisherProxyConfig = false',
  "action: 'set_upload_post_key'",
  'formatPlatformAccountLabel',
  'currentLinkedInOrgName',
  "accountNote || 'Connected'",
], 'ConnectPanel cloud OAuth contract');

includesAll(accountLabel, [
  'isRawPlatformIdentifier',
  "case 'youtube':",
  'channel_title',
  "case 'gbp':",
  'location_name',
], 'ConnectPanel account label utility contract');

excludesAll(panel, [
  'Object.entries(details).filter',
  'map(([k, v]) => `${k}: ${v}`)',
], 'ConnectPanel account note privacy contract');

appearsInOrder(panel, [
  'Social Platforms',
  'API Posting Proxy',
  'Photo Feed Sources',
  'Customer Data Sources',
], 'ConnectPanel group order contract');

includesAll(hook, [
  'export function useConnect(clientId, supabaseUrl, getToken)',
  'Authorization: `Bearer ${token}`',
  'encodeURIComponent(clientId)',
  'request_id: crypto.randomUUID()',
  'has_upload_post_ready',
], 'useConnect authenticated status contract');

includesAll(styles, [
  '.sc-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }',
  '.sc-row-support-form',
], 'ConnectPanel button layout contract');

const rawValues = [
  '123456789012345',
  '17841400000000000',
  'urn:li:person:abc123',
  'urn:li:organization:999999',
  'UCabcdefABCDEF1234567890',
  'accounts/123456789/locations/987654321',
];

for (const value of rawValues) {
  assert.equal(isRawPlatformIdentifier(value), true, `Expected raw identifier to be blocked: ${value}`);
}

const accountLabelCases = [
  {
    platform: 'facebook',
    details: {
      page_id: '123456789012345',
      page_name: 'Scale Small AI',
      ig_user_id: '17841400000000000',
      ig_username: 'scalesmallai',
    },
    expected: 'Scale Small AI',
  },
  {
    platform: 'instagram',
    details: { ig_user_id: '17841400000000000', username: 'scalesmallai' },
    expected: '@scalesmallai',
  },
  {
    platform: 'x',
    details: { username: 'scalesmallai' },
    expected: '@scalesmallai',
  },
  {
    platform: 'tiktok',
    details: { username: 'Scale Small AI', display_name: 'Scale Small AI' },
    expected: 'Scale Small AI',
  },
  {
    platform: 'linkedin',
    details: {
      author_urn: 'urn:li:person:abc123',
      org_urn: 'urn:li:organization:999999',
      available_orgs: [{ urn: 'urn:li:organization:999999', name: 'Scale Small AI' }],
    },
    expected: 'Scale Small AI',
  },
  {
    platform: 'youtube',
    details: { channel_id: 'UCabcdefABCDEF1234567890', channel_title: 'Scale Small AI' },
    expected: 'Scale Small AI',
  },
  {
    platform: 'gbp',
    details: { location: 'accounts/123456789/locations/987654321', location_name: 'Scale Small AI' },
    expected: 'Scale Small AI',
  },
  {
    platform: 'website',
    details: { domain: 'scalesmall.ai' },
    expected: 'scalesmall.ai',
  },
];

const renderedAccountLabels = accountLabelCases
  .map(({ platform, details, expected }) => {
    const label = formatPlatformAccountLabel(platform, details);
    assert.equal(label, expected, `${platform} account label should be human-readable`);
    return label;
  })
  .join('\n');

for (const rawValue of rawValues) {
  assert(!renderedAccountLabels.includes(rawValue), `Rendered account labels should not contain raw identifier: ${rawValue}`);
}

assert.equal(formatPlatformAccountLabel('youtube', { channel_id: 'UCabcdefABCDEF1234567890' }), null, 'YouTube raw channel IDs must not display alone');
assert.equal(formatPlatformAccountLabel('gbp', { location: 'accounts/123456789/locations/987654321' }), null, 'GBP raw location paths must not display alone');

console.log('Shared ConnectPanel cloud contract verified.');
