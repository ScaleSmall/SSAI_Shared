#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

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
  'isRawPlatformIdentifier',
  'currentLinkedInOrgName',
  "case 'youtube':",
  'channel_title',
  "accountNote || 'Connected'",
], 'ConnectPanel cloud OAuth contract');

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

console.log('Shared ConnectPanel cloud contract verified.');
