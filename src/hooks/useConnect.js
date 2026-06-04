import { useState, useEffect, useMemo, useCallback } from 'react';
import { PLATFORM_ORDER, PLATFORM_META, buildConnectUrls } from '../config.js';

async function authHeaders(getToken) {
  const token = getToken ? await getToken() : null;
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export function useConnect(clientId, supabaseUrl, getToken) {
  const [platforms, setPlatforms] = useState(null);
  const [connectors, setConnectors] = useState(null);
  const [uploadPostStatus, setUploadPostStatus] = useState({
    hasKey: false,
    hasUser: false,
    ready: false,
  });
  const [error, setError] = useState(null);

  const { oauthStatusUrl, connectorStatusUrl } = useMemo(
    () => buildConnectUrls(supabaseUrl), [supabaseUrl]
  );

  const fetchPlatforms = useCallback(async () => {
    if (!clientId) return;
    try {
      const headers = await authHeaders(getToken);
      const res = await fetch(`${oauthStatusUrl}?client_id=${encodeURIComponent(clientId)}`, { headers });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setPlatforms(data.platforms || []);
      setUploadPostStatus({
        hasKey: Boolean(data.has_upload_post_key),
        hasUser: Boolean(data.has_upload_post_user),
        ready: Boolean(data.has_upload_post_ready),
      });
      setError(null);
    } catch (err) {
      setError(`Failed to load platforms: ${err.message}`);
    }
  }, [clientId, oauthStatusUrl, getToken]);

  const fetchConnectors = useCallback(async () => {
    if (!clientId) return;
    try {
      const headers = await authHeaders(getToken);
      const res = await fetch(`${connectorStatusUrl}?client_id=${encodeURIComponent(clientId)}`, { headers });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      // Use all_connectors (includes coming_soon); fall back to my_connectors for older API
      setConnectors(data.all_connectors || data.my_connectors || []);
    } catch (err) {
      console.error('Failed to load connectors:', err);
      setConnectors([]);
    }
  }, [clientId, connectorStatusUrl, getToken]);

  useEffect(() => {
    fetchPlatforms();
    fetchConnectors();
  }, [fetchPlatforms, fetchConnectors]);

  const refresh = useCallback(() => {
    fetchPlatforms();
    fetchConnectors();
  }, [fetchPlatforms, fetchConnectors]);

  const counts = useMemo(() => {
    if (!platforms) return { connected: 0, expired: 0, needsSetup: 0, disabled: 0 };
    let connected = 0, expired = 0, needsSetup = 0, disabled = 0;
    for (const p of platforms) {
      const meta = PLATFORM_META[p.platform];
      if (!meta || meta.hidden) continue;
      if (p.connected && !p.is_expired) connected++;
      else if (p.is_expired) expired++;
      else if (!p.enabled) disabled++;
      else needsSetup++;
    }
    return { connected, expired, needsSetup, disabled };
  }, [platforms]);

  const sortedPlatforms = useMemo(() => {
    if (!platforms) return [];
    return PLATFORM_ORDER
      .map(pid => platforms.find(p => p.platform === pid))
      .filter(p => p && PLATFORM_META[p.platform] && !PLATFORM_META[p.platform].hidden)
      .sort((a, b) => {
        const order = (p) => (!p.connected && !p.is_expired && p.enabled) ? 0 : p.is_expired ? 1 : !p.enabled ? 3 : 2;
        return order(a) - order(b);
      });
  }, [platforms]);

  const disconnectPlatform = useCallback(async (platform) => {
    if (!clientId) return;
    try {
      const headers = await authHeaders(getToken);
      const res = await fetch(oauthStatusUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({ client_id: clientId, action: 'disconnect_platform', platform, request_id: crypto.randomUUID() }),
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);
      await fetchPlatforms();
      return data;
    } catch (err) {
      setError(`Failed to disconnect ${platform}: ${err.message}`);
      throw err;
    }
  }, [clientId, oauthStatusUrl, fetchPlatforms, getToken]);

  return {
    platforms, connectors, sortedPlatforms, counts,
    uploadPostStatus,
    error, loading: !platforms,
    refresh, fetchPlatforms, fetchConnectors,
    disconnectPlatform,
    connectorStatusUrl,
    oauthStatusUrl,
  };
}
