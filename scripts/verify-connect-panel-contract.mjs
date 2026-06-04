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

const panel = await load('src/components/ConnectPanel.jsx');
const hook = await load('src/hooks/useConnect.js');

includesAll(panel, [
  "new Set(['hubspot', 'gohighlevel', 'salesforce'])",
  'CRM / Customer Data Sources',
  'format: \'json\'',
  'return_to: `${window.location.origin}/oauth-complete`',
  'Authorization: `Bearer ${token}`',
  'onStartOAuth(c.connector_type)',
  'Connect ${c.display_name}',
], 'ConnectPanel cloud OAuth contract');

includesAll(hook, [
  'export function useConnect(clientId, supabaseUrl, getToken)',
  'Authorization: `Bearer ${token}`',
  'encodeURIComponent(clientId)',
  'request_id: crypto.randomUUID()',
], 'useConnect authenticated status contract');

console.log('Shared ConnectPanel cloud contract verified.');
