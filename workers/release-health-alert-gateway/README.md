# Release health alert gateway

This zero-dependency Cloudflare Worker provides the single public transport boundary for release-health controller alerts.

## Contract

- `POST https://alerts.scalesmall.ai/release-health-alert` accepts only `application/json` with no query string.
- `X-SSAI-Alert-Id` and `X-SSAI-Alert-Signature` must each be exactly 64 lowercase hexadecimal characters.
- The raw request body is streamed into a bounded 4,096-byte buffer and forwarded unchanged to the fixed production `system-failure-ingest` endpoint.
- Only the content type, alert ID, and alert signature are forwarded. Authorization, cookies, forwarding headers, and all other caller headers are discarded.
- Upstream redirects, non-2xx responses, network failures, responses over 65,536 bytes, and responses that do not complete within 10 seconds fail closed with a generic response.
- Every 2xx upstream result, including an idempotent replay result, is returned as the same empty 2xx status.
- `GET https://alerts.scalesmall.ai/healthz` reports only the versioned gateway component and healthy liveness state used by the controller activation gate.
- Candidate versions expose the same health response only on the exact protected preview alias shape and only when the request repeats that exact hostname in `X-SSAI-Preview-Health-Host`. Arbitrary `*.workers.dev` hosts and all preview-host alert POSTs remain rejected.
- Before quota is consumed, the Worker strictly parses the canonical version-2 body, recomputes its domain-separated alert ID, and verifies the exact body HMAC in constant time using the `ALERT_HMAC_KEY` secret binding. Malformed, noncanonical, oversized, timed-out, or tampered requests fail closed without touching authenticated delivery capacity.
- Authenticated alert ingestion is fail-closed behind the exact Cloudflare `ALERT_INGEST_RATE_LIMITER` binding: namespace `735104001`, 60 requests per 60 seconds. Health is unhealthy if that binding is unavailable.
- All responses are non-cacheable. The Worker has exactly one secret binding, `ALERT_HMAC_KEY`, and never logs, returns, forwards, or includes its value in deployment evidence.

The Supabase ingest function remains the authentication, signature-verification, deduplication, persistence, and notification boundary. This Worker only supplies a stable custom domain and a narrow, bounded forwarding contract.

## Verification

Run `npm run check:release-health-alert-gateway`. The focused contract test covers the accepted path, authentication-before-quota ordering, fake-header floods, tamper and noncanonical rejection, exact byte and header forwarding, 2xx replay behavior, route and header rejection, size and body-read time limits, limiter failure, redirects, upstream failures, bounded response handling, and health response.

Deployment must use the protected Shared release workflow. It uploads an immutable exact-commit candidate, attests only the exact rate limiter and `ALERT_HMAC_KEY` secret bindings without reading the secret value, validates the exact candidate preview before traffic, rechecks the preflight-attested 100-percent production version, and promotes only the candidate version. Any post-mutation failure automatically restores only that attested prior version.

The first bootstrap is disabled unless the protected dispatch explicitly authorizes it. Bootstrap creates the Worker with no routes, verifies that `alerts.scalesmall.ai` remains unattached, then follows the same candidate preview and promotion gates. This contains an incomplete first release without publishing an unverified public route. DNS or route deletion is never a rollback mechanism because it converts a controlled transport failure into an unobservable outage.
