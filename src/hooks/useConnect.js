import { useState, useEffect, useMemo, useCallback } from 'react';
import { PLATFORM_ORDER, PLATFORM_META, buildConnectUrls } from '../config.js';

/**
 * Hook that manages Connect state — platforms, connectors, counts.
 * Both SSAI_Connect and SSAI_Dashboard use this same hook.
 *
 * @param {string} clientId - The n8n_client_id
 * @param {string} supabaseUrl - Base Supabase URL (for building function URLs)
 * @returns {object} Connect state and actions
 */
export function useConnect(clientId, supabaseUrl) {
  const [platforms, setPlatforms] = useState(null);
  const [connectors, setConnectors] = useState(null);
  const [error, setError] = useState(null);

  const { oauthStatusUrl, connectorStatusUrl } = useMemo(
    () => buildConnectUrls(supabaseUrl), [supabaseUrl]
  );

  const fetchPlatforms = useCallback(async () => {
    if (!clientId) return;
    try {
      const res = await fetch(`${oauthStatusUrl}?client_id=${clientId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setPlatforms(data.platforms || []);
      setError(null);
    } catch (err) {
      setError(`Failed to load platforms: ${err.message}`);
    }
  }, [clientId, oauthStatusUrl]);

  const fetchConnectors = useCallback(async () => {
    if (!clientId) return;
    try {
      const res = await fetch(`${connectorStatusUrl}?client_id=${clientId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setConnectors(data.my_connectors || []);
    } catch (err) {
      console.error('Failed to load connectors:', err);
      setConnectors([]);
    }
  }, [clientId, connectorStatusUrl]);

  useEffect(() => {
    fetchPlatforms();
    fetchConnectors();
  }, [fetchPlatforms, fetchConnectors]);

  const refresh = useCallback(() => {
    fetchPlatforms();
    fetchConnectors();
  }, [fetchPlatforms, fetchConnectors]);

  // Counts
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

  // Sorted platforms (needs-setup first, then expired, then connected, then disabled)
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

  return {
    platforms, connectors, sortedPlatforms, counts,
    error, loading: !platforms,
    refresh, fetchPlatforms, fetchConnectors,
    connectorStatusUrl,
  };
}
