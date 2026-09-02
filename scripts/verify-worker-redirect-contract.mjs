import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { convertV4MiniflareOptions, Miniflare } from 'miniflare';

const sources = [
  ['github', new URL('../workers/release-health-controller/src/github-api.mjs', import.meta.url), 2],
  ['controller-alert', new URL('../workers/release-health-controller/src/alerts.mjs', import.meta.url), 1],
  ['alert-gateway', new URL('../workers/release-health-alert-gateway/src/index.mjs', import.meta.url), 1],
];
for (const [name, url, expectedManualCount] of sources) {
  const source = await readFile(url, 'utf8');
  assert.doesNotMatch(source, /redirect:\s*['"]error['"]/, `${name} must not use Worker-incompatible redirect mode`);
  assert.equal(
    source.match(/redirect:\s*['"]manual['"]/g)?.length ?? 0,
    expectedManualCount,
    `${name} must pin every outbound request to manual redirect mode`,
  );
}

async function verifyRuntime(compatibilityDate) {
  const outboundRequests = [];
  const runtime = new Miniflare(convertV4MiniflareOptions({
    compatibilityDate,
    modules: true,
    script: `
    export default {
      async fetch() {
        const results = [];
        for (const request of [
          {
            url: 'https://api.github.com/repos/ScaleSmall/SSAI_Shared/commits/main',
            init: {
              method: 'GET',
              redirect: 'manual',
              headers: { Authorization: 'Bearer synthetic-runtime-token' },
            },
          },
          {
            url: 'https://alerts.scalesmall.ai/release-health-alert',
            init: {
              method: 'POST',
              redirect: 'manual',
              headers: { 'Content-Type': 'application/json' },
              body: '{}',
            },
          },
        ]) {
          const response = await fetch(request.url, request.init);
          results.push({
            status: response.status,
            redirected: response.redirected,
            location_present: response.headers.has('location'),
          });
        }
        let incompatible_mode_rejected = false;
        try {
          await fetch('https://api.github.com/repos/ScaleSmall/SSAI_Shared/commits/main', {
            method: 'GET',
            redirect: 'error',
          });
        } catch {
          incompatible_mode_rejected = true;
        }
        return Response.json({ incompatible_mode_rejected, results });
      },
    };
    `,
    outboundService: async (request) => {
      outboundRequests.push(Object.freeze({ method: request.method, url: request.url }));
      return new Response('', {
        status: 302,
        headers: { Location: 'https://redirect-target.invalid/credential-capture' },
      });
    },
  }));

  try {
    const response = await runtime.dispatchFetch('https://worker-contract.invalid/');
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.incompatible_mode_rejected, true);
    assert.deepEqual(result.results, [
      { status: 302, redirected: false, location_present: true },
      { status: 302, redirected: false, location_present: true },
    ]);
    assert.deepEqual(outboundRequests, [
      { method: 'GET', url: 'https://api.github.com/repos/ScaleSmall/SSAI_Shared/commits/main' },
      { method: 'POST', url: 'https://alerts.scalesmall.ai/release-health-alert' },
    ]);
  } finally {
    await runtime.dispose();
  }
}

for (const compatibilityDate of ['2026-08-27', '2026-08-31']) {
  await verifyRuntime(compatibilityDate);
}

console.log('Worker redirect request-construction contract verified.');
