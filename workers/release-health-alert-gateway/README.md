# Release health alert gateway

This zero-dependency Cloudflare Worker provides the single public transport boundary for release-health controller alerts.

## Contract

- `POST https://alerts.scalesmall.ai/release-health-alert` accepts only `application/json` with no query string.
- `X-SSAI-Alert-Id` and `X-SSAI-Alert-Signature` must each be exactly 64 lowercase hexadecimal characters.
- The raw request body is streamed into a bounded 4,096-byte buffer and forwarded unchanged to the fixed production `system-failure-ingest` endpoint.
- Only the content type, alert ID, and alert signature are forwarded. Authorization, cookies, forwarding headers, and all other caller headers are discarded.
- Upstream requests use Worker-compatible manual redirect handling. Redirects fail closed without following the location or forwarding alert credentials; other non-2xx responses, network failures, responses over 65,536 bytes, and responses that do not complete within 10 seconds also return a generic failure.
- Every 2xx upstream result, including an idempotent replay result, is returned as the same empty 2xx status.
- `GET https://alerts.scalesmall.ai/healthz` reports only the versioned gateway component and healthy liveness state used by the controller activation gate. Production health requires both a valid runtime version ID and the exact 40-hex deployment tag.
- Candidate versions expose health only on their immutable `<8-hex-version-prefix>-ssai-release-health-alert-gateway.<account-subdomain>.workers.dev` hostname and only when the request repeats that exact hostname in `X-SSAI-Preview-Health-Host`. The probe calls the isolated `immutable-preview-health` limiter key to prove the rate-limiter binding path. Preview health remains healthy with `version_id: null` when Cloudflare omits runtime version metadata; when metadata is present, its valid ID must match the immutable hostname prefix. Temporary commit aliases, arbitrary `*.workers.dev` hosts, mismatched preview headers, and all preview-host alert POSTs remain rejected.
- Before quota is consumed, the Worker strictly parses the canonical version-2 body, recomputes its domain-separated alert ID, and verifies the exact body HMAC in constant time using the `ALERT_HMAC_KEY` secret binding. Malformed, noncanonical, oversized, timed-out, or tampered requests fail closed without touching authenticated delivery capacity.
- Authenticated alert ingestion is fail-closed behind the exact Cloudflare `ALERT_INGEST_RATE_LIMITER` binding: namespace `735104001`, 60 requests per 60 seconds. Health is unhealthy if that binding is unavailable.
- All responses are non-cacheable. The Worker has exactly one secret binding, `ALERT_HMAC_KEY`, and never logs, returns, forwards, or includes its value in deployment evidence.

The Supabase ingest function remains the authentication, signature-verification, deduplication, persistence, and notification boundary. This Worker only supplies a stable custom domain and a narrow, bounded forwarding contract.

## Verification

Run `npm run check:release-health-alert-gateway`. The focused contract test covers the accepted path, authentication-before-quota ordering, fake-header floods, tamper and noncanonical rejection, exact byte and header forwarding, 2xx replay behavior, route and header rejection, size and body-read time limits, limiter failure, redirects, upstream failures, bounded response handling, and health response.

Deployment must use the protected Shared release workflow. It uploads an immutable exact-commit candidate, attests only the exact rate limiter and `ALERT_HMAC_KEY` secret bindings without reading the secret value, validates the exact candidate preview before traffic, rechecks the preflight-attested 100-percent production version, and promotes only the candidate version. Any post-mutation failure automatically restores only that attested prior version.

Custom-domain attachment records the exact run-owned immutable Cloudflare domain identifier as soon as Cloudflare confirms stable hostname, service, zone, and environment identity. Domain identifiers are treated as opaque and accepted only in Cloudflare's documented or observed 32-hex, 40-hex, or canonical lowercase UUID forms; every later inventory, detail, receipt, and rollback comparison still requires exact equality. Certificate issuance remains a separate bounded readiness gate. This prevents normal certificate provisioning from being misclassified as an identity conflict while preserving strict final certificate attestation. If readiness fails, rollback may remove only the persisted exact run-owned domain after re-proving its stable identity; ambiguous or contradictory ownership still leaves candidate traffic contained rather than risking deletion of another actor's domain.

The first bootstrap is disabled unless the protected dispatch explicitly authorizes it. Bootstrap creates the Worker with no routes, verifies that `alerts.scalesmall.ai` remains unattached, then follows the same candidate preview and promotion gates. This contains an incomplete first release without publishing an unverified public route. DNS or route deletion is never a rollback mechanism because it converts a controlled transport failure into an unobservable outage.
