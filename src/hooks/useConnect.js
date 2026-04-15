import { useCallback, useEffect, useMemo, useState } from 'react';

export function useConnect({ clientId, supabaseUrl }) {
  const [platforms, setPlatforms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const oauthStatusUrl = useMemo(() => {
    if (!supabaseUrl) return '';
    return `${supabaseUrl}/functions/v1/oauth-status`;
  }, [supabaseUrl]);

  const disconnectUrl = useMemo(() => {
    if (!supabaseUrl) return '';
    return `${supabaseUrl}/functions/v1/oauth-disconnect`;
  }, [supabaseUrl]);

  const fetchPlatforms = useCallback(async () => {
    if (!oauthStatusUrl || !clientId) {
      setPlatforms([]);
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError('');

      const returnTo = encodeURIComponent(
        typeof window !== 'undefined'
          ? window.location.origin
          : 'https://connect.scalesmall.ai'
      );

      const res = await fetch(
        `${oauthStatusUrl}?client_id=${clientId}&return_to=${returnTo}`
      );

      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `oauth-status failed with ${res.status}`);
      }

      const data = await res.json();
      const nextPlatforms = Array.isArray(data?.platforms) ? data.platforms : [];
      setPlatforms(nextPlatforms);
    } catch (err) {
      console.error('[useConnect] fetchPlatforms failed', err);
      setError(err?.message || 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, [oauthStatusUrl, clientId]);

  const disconnectPlatform = useCallback(
    async (platform) => {
      if (!disconnectUrl || !clientId || !platform) {
        throw new Error('Missing disconnect configuration');
      }

      const res = await fetch(disconnectUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: clientId,
          platform,
        }),
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `oauth-disconnect failed with ${res.status}`);
      }

      return res.json();
    },
    [disconnectUrl, clientId]
  );

  const refreshPlatforms = useCallback(async () => {
    await fetchPlatforms();
  }, [fetchPlatforms]);

  useEffect(() => {
    fetchPlatforms();
  }, [fetchPlatforms]);

  return {
    platforms,
    loading,
    error,
    refreshPlatforms,
    disconnectPlatform,
  };
}

export default useConnect;
