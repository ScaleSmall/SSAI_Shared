import React, { useState } from 'react';
import { useConnect } from '../hooks/useConnect.js';
import { PLATFORM_META, CONNECTOR_ICONS } from '../config.js';
import PlatformIcon from './PlatformIcon.jsx';
import ConnectorIcon from './ConnectorIcon.jsx';
import EmailIdentity from './EmailIdentity.jsx';
import DataSourcePanel from './DataSourcePanel.jsx';

/**
 * Full Connect panel — connectors, platforms, and service-gated sections.
 * Drop this into any ScaleSmall app.
 *
 * @param {string} clientId - n8n_client_id
 * @param {string} supabaseUrl - Base Supabase URL
 * @param {string} businessName - Display name for the business
 * @param {string[]} [services] - Enabled service slugs (e.g., ['repeat_referral','jobs_to_socials'])
 * @param {function} [getToken] - Returns current session access_token (needed for R&R sections)
 * @param {string} [className] - Optional wrapper class
 */
export default function ConnectPanel({ clientId, supabaseUrl, businessName, services, getToken, className }) {
  const { sortedPlatforms, connectors, counts, error, loading, refresh, disconnectPlatform, connectorStatusUrl } = useConnect(clientId, supabaseUrl);
  const hasRR = services && (services.includes('repeat_referral') || services.includes('customer_intelligence'));

  if (!clientId) return (
    <div className={`sc-panel ${className || ''}`}>
      <div className="sc-error">No client ID linked to your account yet. Complete onboarding first.</div>
    </div>
  );

  return (
    <div className={`sc-panel ${className || ''}`}>
      {/* Status bar */}
      <div className="sc-status-bar">
        <div className="sc-stat"><span className="sc-dot sc-dot-green" />{counts.connected} connected</div>
        {counts.expired > 0 && <div className="sc-stat"><span className="sc-dot sc-dot-amber" />{counts.expired} expired</div>}
        {counts.needsSetup > 0 && <div className="sc-stat"><span className="sc-dot sc-dot-red" />{counts.needsSetup} needs setup</div>}
      </div>

      {error && <div className="sc-error">{error}</div>}

      {loading ? <div className="sc-loading"><div className="sc-spinner" />Loading…</div> : <>
        {/* Connectors first */}
        {connectors?.length > 0 && <>
          <div className="sc-section-label">Connectors</div>
          <p className="sc-subtitle">Connect your photo source so we can automatically import job site photos.</p>
          <div className="sc-list">
            {connectors.map(c => (
              <ConnectorRow key={c.connector_type} c={c} clientId={clientId} endpoint={connectorStatusUrl} onRefresh={refresh} />
            ))}
          </div>
        </>}

        {/* Platforms */}
        <div className="sc-section-label" style={{ marginTop: connectors?.length > 0 ? 24 : 0 }}>Platforms</div>
        <div className="sc-list">
          {sortedPlatforms.map((p, i) => (
            <PlatformRow key={p.platform} p={p} clientId={clientId} supabaseUrl={supabaseUrl} i={i} onDisconnect={disconnectPlatform} onRefresh={refresh} />
          ))}
        </div>

        {/* R&R Service sections — only visible if repeat_referral or customer_intelligence is enabled */}
        {hasRR && getToken && <>
          <div className="sc-rr-divider" />
          <EmailIdentity supabaseUrl={supabaseUrl} getToken={getToken} />
          <DataSourcePanel supabaseUrl={supabaseUrl} getToken={getToken} />
        </>}
      </>}
    </div>
  );
}

// ===== Platform Row =====
function PlatformRow({ p, clientId, supabaseUrl, i, onDisconnect, onRefresh }) {
  const [showEmbed, setShowEmbed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  const meta = PLATFORM_META[p.platform];
  if (!meta) return null;

  const redirectUrl = encodeURIComponent(window.location.origin + window.location.pathname);
  const connectUrl = p.connect_url ? p.connect_url + '&redirect_after=' + redirectUrl : '#';
  const isWebsite = p.platform === 'website';
  const details = p.details || {};

  const handleDisconnect = async () => {
    setDisconnecting(true);
    try {
      await onDisconnect(p.platform);
      setConfirmDisconnect(false);
    } catch (e) { /* error handled in hook */ }
    finally { setDisconnecting(false); }
  };

  let statusBadge, action;
  if (p.connected && !p.is_expired) {
    statusBadge = <span className="sc-badge sc-badge-green">Connected</span>;
    if (isWebsite) {
      action = <button className="sc-btn sc-btn-ghost" onClick={() => setShowEmbed(!showEmbed)}>{showEmbed ? 'Hide code' : 'Embed code'}</button>;
    } else if (!meta.noOAuth) {
      action = confirmDisconnect
        ? <span className="sc-confirm-row">
            <button className="sc-btn sc-btn-danger" onClick={handleDisconnect} disabled={disconnecting}>{disconnecting ? 'Disconnecting...' : 'Confirm'}</button>
            <button className="sc-btn sc-btn-ghost" onClick={() => setConfirmDisconnect(false)}>Cancel</button>
          </span>
        : <button className="sc-btn sc-btn-ghost sc-btn-disconnect" onClick={() => setConfirmDisconnect(true)}>Disconnect</button>;
    }
  } else if (p.is_expired) {
    statusBadge = <span className="sc-badge sc-badge-amber">Expired</span>;
    action = !meta.noOAuth && <a href={connectUrl} className="sc-btn sc-btn-warn">Reconnect</a>;
  } else if (!p.enabled) {
    statusBadge = <span className="sc-badge sc-badge-off">Disabled</span>;
  } else {
    statusBadge = <span className="sc-badge sc-badge-red">Not connected</span>;
    if (isWebsite) action = <button className="sc-btn sc-btn-primary" onClick={() => setShowEmbed(!showEmbed)}>Get embed code</button>;
    else if (meta.noOAuth) action = meta.derived ? <span className="sc-badge sc-badge-off">Connect Facebook first</span> : null;
    else action = <a href={connectUrl} className="sc-btn sc-btn-primary">Connect</a>;
  }

  const embedCode = `<script src="${supabaseUrl}/functions/v1/widget-gallery?format=js" data-client="${clientId}"><\/script>`;
  const handleCopy = () => { navigator.clipboard.writeText(embedCode); setCopied(true); setTimeout(() => setCopied(false), 2500); };

  return (
    <div className="sc-row" style={{ animationDelay: `${i * 0.03}s` }}>
      <div className="sc-row-main">
        <div className="sc-icon" style={{ background: meta.color, color: '#fff' }}>
          <PlatformIcon platform={p.platform} />
        </div>
        <div className="sc-info">
          <div className="sc-name">{meta.name}</div>
          <div className="sc-note">
            {p.connected && !p.is_expired
              ? (Object.entries(details).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`).join(' · ') || 'Connected')
              : meta.note}
          </div>
        </div>
        <div className="sc-actions">{statusBadge}{action}</div>
      </div>
      {isWebsite && showEmbed && (
        <div className="sc-embed">
          <p className="sc-embed-label">Paste this on your website where you want the gallery:</p>
          <div className="sc-embed-row">
            <code className="sc-embed-code">{embedCode}</code>
            <button className="sc-btn sc-btn-ghost" onClick={handleCopy}>{copied ? '✓ Copied' : 'Copy'}</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ===== Connector Row =====
function ConnectorRow({ c, clientId, endpoint, onRefresh }) {
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const icon = CONNECTOR_ICONS[c.connector_type] || '🔌';
  const isConnected = c.status === 'connected';

  const handleConnect = async () => {
    setLoading(true); setError(null);
    try {
      const body = { connector_type: c.connector_type, client_id: clientId };
      if (c.auth_type === 'api_key') {
        if (!token.trim()) { setError('Enter your API token'); setLoading(false); return; }
        body.api_token = token.trim();
      }
      const res = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || 'Failed');
      setToken('');
      if (onRefresh) onRefresh();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const handleDisconnect = async () => {
    setLoading(true);
    try {
      await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ connector_type: c.connector_type, client_id: clientId, action: 'disconnect' }) });
      if (onRefresh) onRefresh();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className={`sc-row ${isConnected ? 'sc-row-connected' : ''}`}>
      <div className="sc-row-main">
        <div className="sc-icon sc-icon-connector"><ConnectorIcon type={c.connector_type} /></div>
        <div className="sc-info">
          <div className="sc-name">{c.display_name}</div>
          <div className="sc-note">{c.description}</div>
          {isConnected && c.photos_imported > 0 && (
            <div className="sc-note">{c.photos_imported} photos imported · Last: {c.last_polled_at ? new Date(c.last_polled_at).toLocaleDateString() : 'Never'}</div>
          )}
        </div>
        <div className="sc-actions">
          <span className={`sc-badge ${isConnected ? 'sc-badge-green' : 'sc-badge-amber'}`}>{isConnected ? 'Connected' : 'Setup Required'}</span>
          {isConnected && <button className="sc-btn sc-btn-danger" onClick={handleDisconnect} disabled={loading}>Disconnect</button>}
        </div>
      </div>
      {!isConnected && c.auth_type === 'api_key' && (
        <div className="sc-setup">
          {c.setup_instructions?.steps && <ol className="sc-steps">{c.setup_instructions.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>}
          <div className="sc-token-row">
            <input type="password" placeholder="Paste your API token" value={token} onChange={e => setToken(e.target.value)} className="sc-input" />
            <button className="sc-btn sc-btn-primary" onClick={handleConnect} disabled={loading}>{loading ? 'Connecting...' : 'Connect'}</button>
          </div>
          {error && <div className="sc-row-error">{error}</div>}
        </div>
      )}
    </div>
  );
}

export { PlatformRow, ConnectorRow };
