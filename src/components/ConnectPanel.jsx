import React, { useState } from 'react';
import { useConnect } from '../hooks/useConnect.js';
import { PLATFORM_META } from '../config.js';
import PlatformIcon from './PlatformIcon.jsx';
import ConnectorIcon from './ConnectorIcon.jsx';
import EmailIdentity from './EmailIdentity.jsx';
import DataSourcePanel from './DataSourcePanel.jsx';

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
      <div className="sc-status-bar">
        <div className="sc-stat"><span className="sc-dot sc-dot-green" />{counts.connected} connected</div>
        {counts.expired > 0 && <div className="sc-stat"><span className="sc-dot sc-dot-amber" />{counts.expired} expired</div>}
        {counts.needsSetup > 0 && <div className="sc-stat"><span className="sc-dot sc-dot-red" />{counts.needsSetup} needs setup</div>}
      </div>

      {error && <div className="sc-error">{error}</div>}

      {loading ? <div className="sc-loading"><div className="sc-spinner" />Loading…</div> : <>
        {/* Social Platforms */}
        <div className="sc-section-label">Social Platforms</div>
        <p className="sc-subtitle">Connect the socials you actually use — skip the ones you do not use. Most clients connect 2–4. <strong>No need to connect them all.</strong></p>
        <div className="sc-list">
          {sortedPlatforms.map((p, i) => (
            <PlatformRow key={p.platform} p={p} clientId={clientId} supabaseUrl={supabaseUrl} businessName={businessName} i={i} onDisconnect={disconnectPlatform} onRefresh={refresh} />
          ))}
        </div>

        {/* Photo Feed Sources */}
        {connectors && connectors.length > 0 && <>
          <div className="sc-section-label" style={{ marginTop: 24 }}>Photo Feed Sources</div>
          <p className="sc-subtitle">Connect where your team takes job photos. Most clients use 1, maybe 2. <strong>If you use CompanyCam, that is all you need.</strong></p>
          <div className="sc-list">
            {connectors.map(c => (
              <ConnectorRow key={c.connector_type} c={c} clientId={clientId} endpoint={connectorStatusUrl} onRefresh={refresh} />
            ))}
          </div>
        </>}

        {/* R&R Service sections */}
        {hasRR && getToken && <>
          <div className="sc-rr-divider" />
          <EmailIdentity supabaseUrl={supabaseUrl} getToken={getToken} />
          <DataSourcePanel supabaseUrl={supabaseUrl} getToken={getToken} />
        </>}
      </>}
    </div>
  );
}

function PlatformRow({ p, clientId, supabaseUrl, businessName, i, onDisconnect, onRefresh }) {
  const [showEmbed, setShowEmbed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  const [showOrgPicker, setShowOrgPicker] = useState(false);
  const [selectingOrg, setSelectingOrg] = useState(false);
  const [orgMismatchWarning, setOrgMismatchWarning] = useState(null);
  const [pendingOrg, setPendingOrg] = useState(null);
  const meta = PLATFORM_META[p.platform];
  if (!meta) return null;

  const redirectUrl = encodeURIComponent(window.location.origin + window.location.pathname);
  const connectUrl = p.connect_url ? p.connect_url + '&redirect_after=' + redirectUrl : '#';
  const isWebsite = p.platform === 'website';
  const details = p.details || {};

  // LinkedIn-specific state
  const isLinkedIn = p.platform === 'linkedin';
  const liAvailableOrgs = details.available_orgs || [];
  const liCurrentOrgUrn = details.org_urn;
  const liCurrentOrgName = liAvailableOrgs.find(o => o.urn === liCurrentOrgUrn)?.name || details.page_id || '';
  const liNeedsOrgSelection = details.needs_org_selection; // no org set at all
  const liNeedsConfirmation = details.needs_confirmation;  // org set but not confirmed

  const handleSelectOrg = async (org, forceOverride = false) => {
    setSelectingOrg(true);
    setOrgMismatchWarning(null);
    try {
      const res = await fetch(`${supabaseUrl}/functions/v1/linkedin-select-org`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientId, org_urn: org.urn, org_id: org.id, org_name: org.name, force_mismatch: forceOverride }),
      });
      const data = await res.json();
      if (data.warning && data.mismatch && !forceOverride) {
        // Backend says name does not match — show warning and ask to confirm
        setOrgMismatchWarning({ message: data.message, org });
        setPendingOrg(org);
        setSelectingOrg(false);
        return;
      }
      if (!res.ok || data.error) throw new Error(data.error || 'Failed');
      setShowOrgPicker(false);
      setOrgMismatchWarning(null);
      setPendingOrg(null);
      if (onRefresh) onRefresh();
    } catch (e) { console.error('Org select failed:', e); }
    finally { setSelectingOrg(false); }
  };

  const handleConfirmMismatch = () => {
    if (pendingOrg) handleSelectOrg(pendingOrg, true);
  };

  const handleDisconnect = async () => {
    setDisconnecting(true);
    try { await onDisconnect(p.platform); setConfirmDisconnect(false); }
    catch (e) { /* handled in hook */ }
    finally { setDisconnecting(false); }
  };

  let statusBadge, action;
  if (p.connected && !p.is_expired) {
    if (isLinkedIn && liNeedsConfirmation) {
      // Org set but not confirmed — needs admin to verify correct page
      statusBadge = <span className="sc-badge sc-badge-amber">Confirm Page</span>;
      action = <button className="sc-btn sc-btn-warn" onClick={() => setShowOrgPicker(!showOrgPicker)}>
        {showOrgPicker ? 'Cancel' : 'Verify Page'}
      </button>;
    } else {
      statusBadge = <span className="sc-badge sc-badge-green">Connected</span>;
      if (isWebsite) {
        action = <button className="sc-btn sc-btn-ghost" onClick={() => setShowEmbed(!showEmbed)}>{showEmbed ? 'Hide code' : 'Embed code'}</button>;
      } else if (!meta.noOAuth) {
        action = confirmDisconnect
          ? <span className="sc-confirm-row">
              <button className="sc-btn sc-btn-danger" onClick={handleDisconnect} disabled={disconnecting}>{disconnecting ? 'Disconnecting...' : 'Confirm'}</button>
              <button className="sc-btn sc-btn-ghost" onClick={() => setConfirmDisconnect(false)}>Cancel</button>
            </span>
          : <span className="sc-confirm-row">
              {isLinkedIn && <button className="sc-btn sc-btn-ghost sc-btn-xs" onClick={() => setShowOrgPicker(!showOrgPicker)} title="Change LinkedIn page">Change page</button>}
              <button className="sc-btn sc-btn-ghost sc-btn-disconnect" onClick={() => setConfirmDisconnect(true)}>Disconnect</button>
            </span>;
      }
    }
  } else if (p.is_expired) {
    statusBadge = <span className="sc-badge sc-badge-amber">Expired</span>;
    action = !meta.noOAuth && <a href={connectUrl} className="sc-btn sc-btn-warn">Reconnect</a>;
  } else if (!p.enabled) {
    statusBadge = <span className="sc-badge sc-badge-off">Disabled</span>;
  } else if (isLinkedIn && liNeedsOrgSelection) {
    statusBadge = <span className="sc-badge sc-badge-amber">Select Page</span>;
    action = <button className="sc-btn sc-btn-primary" onClick={() => setShowOrgPicker(!showOrgPicker)}>{showOrgPicker ? 'Cancel' : 'Choose Page'}</button>;
  } else {
    statusBadge = <span className="sc-badge sc-badge-red">Not connected</span>;
    if (isWebsite) action = <button className="sc-btn sc-btn-primary" onClick={() => setShowEmbed(!showEmbed)}>Get embed code</button>;
    else if (meta.noOAuth) action = meta.derived ? <span className="sc-badge sc-badge-off">Connect Facebook first</span> : null;
    else action = <a href={connectUrl} className="sc-btn sc-btn-primary">Connect</a>;
  }

  // LinkedIn detail note
  let linkedInNote = null;
  if (isLinkedIn) {
    if (p.connected && !p.is_expired && liCurrentOrgName) {
      linkedInNote = liNeedsConfirmation
        ? `⚠️ Posting to: ${liCurrentOrgName} — please verify this is correct`
        : `Page: ${liCurrentOrgName}`;
    } else if (liNeedsOrgSelection) {
      linkedInNote = 'Authorized — select a LinkedIn page to post to';
    }
  }

  const embedCode = `<script src="${supabaseUrl}/functions/v1/widget-gallery?format=js" data-client="${clientId}"><\/script>`;
  const handleCopy = () => { navigator.clipboard.writeText(embedCode); setCopied(true); setTimeout(() => setCopied(false), 2500); };

  return (
    <div className="sc-row" style={{ animationDelay: `${i * 0.03}s` }}>
      <div className="sc-row-main">
        <div className="sc-icon" style={{ background: meta.color, color: '#fff' }}><PlatformIcon platform={p.platform} /></div>
        <div className="sc-info">
          <div className="sc-name">{meta.name}</div>
          <div className="sc-note">
            {isLinkedIn && linkedInNote
              ? linkedInNote
              : p.connected && !p.is_expired
                ? (Object.entries(details).filter(([k, v]) => v && typeof v !== 'object' && k !== 'method').map(([k, v]) => `${k}: ${v}`).join(' · ') || 'Connected')
                : meta.note}
          </div>
        </div>
        <div className="sc-actions">{statusBadge}{action}</div>
      </div>

      {/* Embed code panel (website) */}
      {isWebsite && showEmbed && (
        <div className="sc-embed">
          <p className="sc-embed-label">Paste this on your website where you want the gallery:</p>
          <div className="sc-embed-row">
            <code className="sc-embed-code">{embedCode}</code>
            <button className="sc-btn sc-btn-ghost" onClick={handleCopy}>{copied ? '✓ Copied' : 'Copy'}</button>
          </div>
        </div>
      )}

      {/* LinkedIn org picker */}
      {isLinkedIn && showOrgPicker && (
        <div className="sc-embed">
          <p className="sc-embed-label">
            {liNeedsConfirmation
              ? 'Verify the correct LinkedIn page for this client:'
              : liCurrentOrgUrn
                ? 'Change which LinkedIn page to post to:'
                : 'Which LinkedIn page should we post to?'}
          </p>
          {businessName && <p className="sc-note" style={{ marginBottom: 10 }}>Client: <strong>{businessName}</strong></p>}

          {/* Mismatch warning */}
          {orgMismatchWarning && (
            <div className="sc-org-mismatch">
              <p>⚠️ {orgMismatchWarning.message}</p>
              <div className="sc-confirm-row" style={{ marginTop: 8 }}>
                <button className="sc-btn sc-btn-danger" onClick={handleConfirmMismatch} disabled={selectingOrg}>
                  Yes, use this page anyway
                </button>
                <button className="sc-btn sc-btn-ghost" onClick={() => { setOrgMismatchWarning(null); setPendingOrg(null); }}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          <div className="sc-org-list">
            {liAvailableOrgs.map((org) => {
              const isCurrent = org.urn === liCurrentOrgUrn;
              const hasMismatch = org.name_mismatch;
              return (
                <button
                  key={org.urn}
                  className={`sc-org-btn ${isCurrent ? 'sc-org-btn-current' : ''} ${hasMismatch ? 'sc-org-btn-mismatch' : ''}`}
                  onClick={() => handleSelectOrg(org)}
                  disabled={selectingOrg || isCurrent}
                  title={hasMismatch ? 'This page name does not match the client business name' : ''}
                >
                  <span className="sc-org-name">
                    {hasMismatch && '⚠️ '}{org.name}
                    {isCurrent && ' ✓'}
                  </span>
                </button>
              );
            })}
          </div>
          {selectingOrg && <p className="sc-note" style={{ marginTop: 8 }}>Saving...</p>}
        </div>
      )}
    </div>
  );
}

function ConnectorRow({ c, clientId, endpoint, onRefresh }) {
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const isConnected = c.status === 'connected';
  const isComingSoon = c.availability_status === 'coming_soon' || c.status === 'coming_soon';

  if (isComingSoon) {
    return (
      <div className="sc-row sc-row-coming-soon">
        <div className="sc-row-main">
          <div className="sc-icon sc-icon-connector"><ConnectorIcon type={c.connector_type} /></div>
          <div className="sc-info">
            <div className="sc-name">{c.display_name}</div>
            <div className="sc-note">{c.description}</div>
          </div>
          <div className="sc-actions">
            <span className="sc-badge sc-badge-coming-soon">Coming Soon</span>
          </div>
        </div>
      </div>
    );
  }

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
