import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Wifi, WifiOff, RefreshCw, CheckCircle, AlertCircle } from 'lucide-react';
import { useConnect } from '../hooks/useConnect';

function StatusBadge({ status }) {
  if (status === 'connected') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-1 text-xs font-medium text-emerald-700 border border-emerald-200">
        <CheckCircle className="h-3.5 w-3.5" />
        Connected
      </span>
    );
  }
  if (status === 'error') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-1 text-xs font-medium text-red-700 border border-red-200">
        <AlertCircle className="h-3.5 w-3.5" />
        Error
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-zinc-100 px-2 py-1 text-xs font-medium text-zinc-700 border border-zinc-200">
      <WifiOff className="h-3.5 w-3.5" />
      Not connected
    </span>
  );
}

function PlatformIcon({ platform }) {
  const base = 'h-5 w-5';
  switch (platform) {
    case 'youtube':
      return <div className={`${base} rounded-sm bg-red-600`} />;
    case 'facebook':
      return <div className={`${base} rounded-sm bg-blue-600`} />;
    case 'instagram':
      return <div className={`${base} rounded-sm bg-pink-600`} />;
    case 'linkedin':
      return <div className={`${base} rounded-sm bg-sky-700`} />;
    case 'x':
      return <div className={`${base} rounded-sm bg-black`} />;
    case 'reddit':
      return <div className={`${base} rounded-sm bg-orange-500`} />;
    case 'pinterest':
      return <div className={`${base} rounded-sm bg-red-700`} />;
    default:
      return <div className={`${base} rounded-sm bg-zinc-400`} />;
  }
}

function PlatformRow({ p, clientId, supabaseUrl, businessName, i, onDisconnect, onRefresh }) {
  const [busy, setBusy] = useState(false);

  const allowedMessageOrigins = useMemo(() => {
    const origins = new Set([
      'https://oyyfpkpzalhxztpcdjgq.supabase.co',
      'https://connect.scalesmall.ai',
      'https://dashboard.scalesmall.ai',
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:54321',
      typeof window !== 'undefined' ? window.location.origin : ''
    ]);
    return Array.from(origins).filter(Boolean);
  }, []);

  useEffect(() => {
    function handleOAuthMessage(event) {
      if (!allowedMessageOrigins.includes(event.origin)) return;
      if (event.data?.type === 'oauth-success' && event.data?.platform === p.platform) {
        console.log(`[ConnectPanel] OAuth success for ${p.platform} — refreshing statuses`);
        if (onRefresh) onRefresh();
      }
    }

    window.addEventListener('message', handleOAuthMessage);
    return () => window.removeEventListener('message', handleOAuthMessage);
  }, [p.platform, onRefresh, allowedMessageOrigins]);

  async function handleConnect() {
    try {
      setBusy(true);
      if (!p.connect_url) {
        throw new Error(`No connect_url for ${p.platform}`);
      }

      const popup = window.open(
        p.connect_url,
        `${p.platform}-oauth`,
        'width=620,height=760,scrollbars=yes,resizable=yes'
      );

      if (!popup) {
        window.location.href = p.connect_url;
        return;
      }

      const popupTimer = setInterval(() => {
        if (popup.closed) {
          clearInterval(popupTimer);
          setBusy(false);
          if (onRefresh) onRefresh();
        }
      }, 1000);

      setTimeout(() => {
        clearInterval(popupTimer);
      }, 5 * 60 * 1000);
    } catch (err) {
      console.error(`[ConnectPanel] Failed to connect ${p.platform}`, err);
      setBusy(false);
    }
  }

  async function handleDisconnect() {
    try {
      setBusy(true);
      await onDisconnect?.(p.platform);
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error(`[ConnectPanel] Failed to disconnect ${p.platform}`, err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="flex items-center justify-between rounded-xl border border-zinc-200 bg-white px-4 py-3 shadow-sm"
      style={{ animationDelay: `${i * 40}ms` }}
    >
      <div className="flex min-w-0 items-center gap-3">
        <PlatformIcon platform={p.platform} />
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-zinc-900">
            {p.display_name || p.platform}
          </div>
          <div className="truncate text-xs text-zinc-500">
            {businessName || clientId}
          </div>
        </div>
      </div>

      <div className="ml-4 flex items-center gap-3">
        <StatusBadge status={p.status} />

        {p.status === 'connected' ? (
          <button
            onClick={handleDisconnect}
            disabled={busy}
            className="inline-flex items-center rounded-lg border border-zinc-300 px-3 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50 disabled:opacity-50"
          >
            {busy ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : null}
            Disconnect
          </button>
        ) : (
          <button
            onClick={handleConnect}
            disabled={busy}
            className="inline-flex items-center rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50"
          >
            {busy ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <Wifi className="mr-2 h-4 w-4" />}
            Connect
          </button>
        )}
      </div>
    </div>
  );
}

export default function ConnectPanel({ clientId, supabaseUrl, businessName }) {
  const navigate = useNavigate();
  const { platforms, loading, error, refreshPlatforms, disconnectPlatform } = useConnect({
    clientId,
    supabaseUrl,
  });

  return (
    <section className="rounded-2xl border border-zinc-200 bg-white p-5 shadow-sm">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-zinc-900">Connected Accounts</h2>
          <p className="text-sm text-zinc-500">
            Connect and manage social platforms for {businessName || clientId}.
          </p>
        </div>
        <button
          onClick={refreshPlatforms}
          className="inline-flex items-center rounded-lg border border-zinc-300 px-3 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50"
        >
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="space-y-3">
          <div className="h-16 animate-pulse rounded-xl bg-zinc-100" />
          <div className="h-16 animate-pulse rounded-xl bg-zinc-100" />
          <div className="h-16 animate-pulse rounded-xl bg-zinc-100" />
        </div>
      ) : error ? (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          Failed to load platform statuses: {error}
        </div>
      ) : (
        <div className="space-y-3">
          {platforms.map((p, i) => (
            <PlatformRow
              key={p.platform}
              p={p}
              clientId={clientId}
              supabaseUrl={supabaseUrl}
              businessName={businessName}
              i={i}
              onDisconnect={disconnectPlatform}
              onRefresh={refreshPlatforms}
            />
          ))}
        </div>
      )}

      <div className="mt-4 border-t border-zinc-200 pt-4">
        <button
          onClick={() => navigate('/dashboard')}
          className="text-sm font-medium text-zinc-600 hover:text-zinc-900"
        >
          Back to Dashboard
        </button>
      </div>
    </section>
  );
}
