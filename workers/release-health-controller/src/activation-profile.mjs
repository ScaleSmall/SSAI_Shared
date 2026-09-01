const encoder = new TextEncoder();

const exactEnvironment = Object.freeze({
  ALERT_SIGNING_EPOCH: 'release-health-alert-hmac-v1',
  ALERT_SINK_URL: 'https://alerts.scalesmall.ai/release-health-alert',
  CANARY_WORKFLOW_ID: '344135917',
  CIRCUIT_COOLDOWN_MINUTES: '60',
  CIRCUIT_FAILURE_LIMIT: '4',
  CIRCUIT_WINDOW_MINUTES: '60',
  DEFAULT_BRANCH: 'main',
  FALLBACK_ADMISSION_HMAC_EPOCH: 'fallback-admission-hmac-v1',
  FALLBACK_WORKFLOW_ID: '344170407',
  GITHUB_APP_CREDENTIAL_EPOCH: 'github-app-credential-v1',
  GRACE_MINUTES: '10',
  HEALTH_ROUTE: 'https://release-health-controller.scalesmall.ai/healthz',
  HEALTH_STALE_AFTER_SECONDS: '300',
  LOGICAL_SLOT_MINUTES: '1,16,31,46',
  NATIVE_MINUTES: '9,24,39,54',
  NATIVE_WORKFLOW_ID: '315630665',
  REPOSITORY: 'ScaleSmall/SSAI_Shared',
  REPOSITORY_ID: '1183552904',
});

export function activationProfile(env) {
  if (!env || !/^[a-f0-9]{64}$/.test(String(env.CONTROLLER_SOURCE_SHA256 ?? ''))) {
    throw new Error('Controller source digest is invalid.');
  }
  for (const [name, value] of Object.entries(exactEnvironment)) {
    if (env[name] !== value) throw new Error(`Controller activation environment ${name} is invalid.`);
  }
  return Object.freeze({
    active_permissions: 'actions:write,contents:read,metadata:read',
    alert_signing_epoch: env.ALERT_SIGNING_EPOCH,
    alert_sink: env.ALERT_SINK_URL,
    api_version: '2026-03-10',
    canary_workflow: `${env.CANARY_WORKFLOW_ID}:.github/workflows/release-health-monitor-v3.yml`,
    circuit_policy: `${env.CIRCUIT_FAILURE_LIMIT}-failures-per-${env.CIRCUIT_WINDOW_MINUTES}-minutes`,
    circuit_cooldown: `${env.CIRCUIT_COOLDOWN_MINUTES}-minutes`,
    controller_cadence: '* * * * *',
    fallback_admission_hmac_epoch: env.FALLBACK_ADMISSION_HMAC_EPOCH,
    fallback_workflow: `${env.FALLBACK_WORKFLOW_ID}:.github/workflows/release-health-monitor-fallback.yml`,
    github_app_credential_epoch: env.GITHUB_APP_CREDENTIAL_EPOCH,
    grace_window: `${env.GRACE_MINUTES}-15-minutes`,
    health_route: env.HEALTH_ROUTE,
    health_stale_after: `${env.HEALTH_STALE_AFTER_SECONDS}-seconds`,
    logical_slot_minutes: env.LOGICAL_SLOT_MINUTES,
    native_workflow: `${env.NATIVE_WORKFLOW_ID}:.github/workflows/release-health-monitor.yml`,
    native_workflow_minutes: env.NATIVE_MINUTES,
    observe_permissions: 'actions:read,contents:read,metadata:read',
    protected_ref: `refs/heads/${env.DEFAULT_BRANCH}`,
    repository: env.REPOSITORY,
    repository_id: Number(env.REPOSITORY_ID),
    schema: 'ssai-release-health-controller-activation-profile-v3',
    source_digest: env.CONTROLLER_SOURCE_SHA256,
  });
}

export function canonicalActivationProfile(env) {
  return JSON.stringify(Object.fromEntries(
    Object.entries(activationProfile(env)).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

export async function activationProfileDigest(env) {
  const bytes = encoder.encode(canonicalActivationProfile(env));
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
    .map((value) => value.toString(16).padStart(2, '0')).join('');
}

export async function verifyActivationProfileEnvironment(env) {
  const expected = await activationProfileDigest(env);
  if (
    !/^[a-f0-9]{64}$/.test(String(env.CONTROLLER_ACTIVATION_PROFILE_SHA256 ?? ''))
    || env.CONTROLLER_ACTIVATION_PROFILE_SHA256 !== expected
  ) throw new Error('Controller activation profile digest is invalid.');
  return expected;
}
