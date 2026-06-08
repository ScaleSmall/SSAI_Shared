#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

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

const packageJson = JSON.parse(await load('package.json'));
const indexSource = await load('src/index.js');
const apiSource = await load('src/api.js');
const entitySource = await load('src/entity-api.js');
const ldpSource = await load('src/ldp-api.js');

assert.equal(packageJson.exports['./api'].default, './src/api.js');
assert.equal(packageJson.exports['./entity-api'].default, './src/entity-api.js');
assert.equal(packageJson.exports['./ldp-api'].default, './src/ldp-api.js');

includesAll(indexSource, [
  "export * from './api.js'",
  "export * from './entity-api.js'",
  "export * from './ldp-api.js'",
], 'shared index API export contract');

includesAll(apiSource, [
  'DEFAULT_TIMEOUT_MS',
  'MAX_RESPONSE_BYTES',
  'normalizePath(path)',
  'AbortController',
  'setTimeout(() => controller.abort()',
  'readJsonWithLimit',
  'safeErrorMessage',
  'createAuthenticatedApi',
], 'shared authenticated API hardening contract');
excludesAll(apiSource, [
  'response.json()',
], 'shared authenticated API bounded read contract');

includesAll(entitySource, [
  "import { createAuthenticatedApi } from './api.js'",
  'export function createEntityApi',
], 'shared entity API export contract');

includesAll(ldpSource, [
  'DEFAULT_LDP_TIMEOUT_MS',
  'MAX_LDP_RESPONSE_BYTES',
  'normalizeLdpPath(path)',
  'AbortController',
  'readJsonWithLimit',
  'safeErrorMessage',
  'createLdpApi',
  'encodeURIComponent(entityId)',
  'encodeURIComponent(correctionId)',
], 'shared LDP API hardening contract');
excludesAll(ldpSource, [
  'response.json()',
], 'shared LDP API bounded read contract');

console.log('Shared API subpath exports verified.');
