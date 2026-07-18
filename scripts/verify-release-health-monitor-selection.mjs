import assert from 'node:assert/strict';
import { latestByIdentity } from './release-health-monitor-utils.mjs';

const checks = latestByIdentity([
  { id: 102, name: 'release-health', app: 'github-actions', status: 'in_progress', started_at: '2026-07-18T09:10:00Z' },
  { id: 101, name: 'release-health', app: 'github-actions', status: 'completed', conclusion: 'failure', started_at: '2026-07-18T09:00:00Z' },
  { id: 103, name: 'release-health', app: 'cloudflare', status: 'completed', conclusion: 'success', started_at: '2026-07-18T09:05:00Z' },
], (check) => `${check.app}:${check.name}`);

assert.deepEqual(checks.map((check) => check.id).sort(), [102, 103], 'newer reruns must replace stale failures without merging different check providers');

const statuses = latestByIdentity([
  { id: 201, context: 'Cloudflare Pages', state: 'failure', created_at: '2026-07-18T09:00:00Z' },
  { id: 202, context: 'Cloudflare Pages', state: 'success', created_at: '2026-07-18T09:05:00Z' },
], (status) => status.context);

assert.equal(statuses.length, 1);
assert.equal(statuses[0].state, 'success', 'latest commit status must replace an older state for the same context');
assert.throws(() => latestByIdentity([{}], () => ''), /identity must not be empty/);

console.log('Release-health latest-check selection verified.');
