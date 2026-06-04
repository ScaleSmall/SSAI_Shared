import React, { useCallback, useMemo, useState, useEffect } from 'react';
import ReactDOM from 'react-dom';
import { useConnect } from '../hooks/useConnect.js';
import { PLATFORM_META } from '../config.js';
import PlatformIcon from './PlatformIcon.jsx';
import ConnectorIcon from './ConnectorIcon.jsx';
import EmailIdentity from './EmailIdentity.jsx';
import DataSourcePanel from './DataSourcePanel.jsx';

const CRM_CONNECTOR_TYPES = new Set(['hubspot', 'gohighlevel', 'salesforce']);
const PHOTO_CONNECTOR_TYPES = new Set([
  'companycam',
  'jobber',
  'dropbox',
  'google_drive',
  'manual_photo_upload',
]);

function connectorCategory(connector) {
  return connector?.setup_instructions?.category || connector?.config?.category || null;
}

function isCustomerDataConnector(connector) {
  return CRM_CONNECTOR_TYPES.has(connector?.connector_type)
    || connectorCategory(connector) === 'customer_data'
    || connectorCategory(connector) === 'crm';
}

function isPhotoConnector(connector) {
  if (PHOTO_CONNECTOR_TYPES.has(connector?.connector_type)) return true;
  return connectorCategory(connector) === 'photo_feed' && !isCustomerDataConnector(connector);
}

function oauthPlatformFor(platform) {
  return platform === 'gbp' ? 'google' : platform;
}

function cleanDisplayText(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function isRawPlatformIdentifier(value) {
  const text = cleanDisplayText(value);
  if (!text) return false;
  return (
    text.startsWith('urn:') ||
    text.includes('/locations/') ||
    text.includes('/accounts/') ||
    /^[0-9]{6,}$/.test(text) ||
    /^UC[A-Za-z0-9_-]{10,}$/.test(text)
  );
}

function formatHandle(value) {
  const text = cleanDisplayText(value);
  if (!text || isRawPlatformIdentifier(text)) return null;
  return text.startsWith('@') ? text : `@${text}`;
}

function firstSafeText(...values) {
  for (const value of values) {
    const text = cleanDisplayText(value);
    if (text && !isRawPlatformIdentifier(text)) return text;
  }
  return null;
}

function currentLinkedInOrgName(details) {
  const orgUrn = cleanDisplayText(details?.org_urn);
  const orgs = Array.isArray(details?.available_orgs) ? details.available_orgs : [];
  const current = orgs.find(org => org?.urn === orgUrn) || null;
  return firstSafeText(
    current?.name,
    current?.display_name,
    current?.localizedName,
    current?.localized_name,
    current?.['organization~']?.localizedName,
  );
}

function formatPlatformAccountLabel(platform, details = {}) {
  switch (platform) {
    case 'facebook':
      return firstSafeText(details.page_name, details.name) || formatHandle(details.ig_username);
    case 'instagram':
      return formatHandle(details.username || details.ig_username);
    case 'x':
    case 'tiktok':
      return formatHandle(details.username || details.display_name);
    case 'linkedin':
      return currentLinkedInOrgName(details);
    case 'youtube':
      return firstSafeText(details.channel_title, details.channel_name);
    case 'gbp':
      return firstSafeText(details.location, details.location_name, details.account_name);
    case 'website':
      return firstSafeText(details.domain);
    default:
      return null;
  }
}

export default function ConnectPanel({ clientId, supabaseUrl, businessName, services, getToken, className, allowPublisherProxyConfig = false }) {
  const { sortedPlatforms, connectors, counts, uploadPostStatus, error, loading, refresh, disconnectPlatform, connectorStatusUrl, oauthStatusUrl } = useConnect(clientId, supabaseUrl, getToken);
  const hasRR = services && (services.includes('repeat_referral') || services.includes('customer_intelligence'));
  const [oauthBusy, setOauthBusy] = useState(false);
  const [oauthError, setOauthError] = useState(null);
  const [uploadPostInput, setUploadPostInput] = useState('');
  const [uploadPostUserInput, setUploadPostUserInput] = useState('');
  const [showUploadPostForm, setShowUploadPostForm] = useState(false);
  const [uploadPostBusy, setUploadPostBusy] = useState(false);
  const [uploadPostError, setUploadPostError] = useState(null);

  const crmConnectors = useMemo(
    () => (connectors || []).filter(isCustomerDataConnector),
    [connectors],
  );
  const photoConnectors = useMemo(
    () => (connectors || []).filter(isPhotoConnector),
    [connectors],
  );

  const authHeaders = useCallback(async () => {
    const token = getToken ? await getToken() : null;
    return {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }, [getToken]);

  const startOAuth = useCallback(async (requestedPlatform) => {
    if (!clientId) return;
    const popup = window.open('', 'oauth_popup', 'popup,width=600,height=700,noopener=no');
    if (!popup) {
      setOauthError('Popup blocked. Please allow popups for this site and try again.');
      return;
    }
    setOauthBusy(true);
    setOauthError(null);
    try {
      const oauthPlatform = oauthPlatformFor(requestedPlatform);
      const params = new URLSearchParams({
        platform: oauthPlatform,
        client_id: clientId,
        return_to: `${window.location.origin}/oauth-complete`,
        format: 'json',
      });
      if (requestedPlatform === 'gbp') params.set('google_product', 'gbp');
      const res = await fetch(`${supabaseUrl}/functions/v1/oauth-start?${params.toString()}`, {
        headers: await authHeaders(),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.auth_url) throw new Error(data.error || `Could not start OAuth (${res.status})`);
      popup.location.href = data.auth_url;
      const timer = setInterval(() => {
        if (popup.closed) {
          clearInterval(timer);
          refresh();
        }
      }, 800);
      setTimeout(() => clearInterval(timer), 5 * 60 * 1000);
    } catch (err) {
      try { popup.close(); } catch {}
      setOauthError(err.message || 'Could not start OAuth.');
    } finally {
      setOauthBusy(false);
    }
  }, [authHeaders, clientId, refresh, supabaseUrl]);

  const saveUploadPostKey = useCallback(async (clear = false) => {
    const key = clear ? '' : uploadPostInput.trim();
    const uploadPostUser = clear ? '' : uploadPostUserInput.trim();
    if (!clear && !key) { setUploadPostError('Enter your UploadPost API key'); return; }
    if (!clear && !uploadPostUser) { setUploadPostError('Enter your UploadPost user/account'); return; }
    setUploadPostBusy(true);
    setUploadPostError(null);
    try {
      const res = await fetch(oauthStatusUrl, {
        method: 'POST',
        headers: await authHeaders(),
        body: JSON.stringify({
          client_id: clientId,
          action: 'set_upload_post_key',
          api_key: key,
          upload_post_user: uploadPostUser,
          request_id: crypto.randomUUID(),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || `Failed to save (${res.status})`);
      setUploadPostInput('');
      setUploadPostUserInput('');
      setShowUploadPostForm(false);
      refresh();
    } catch (err) {
      setUploadPostError(err.message || 'Failed to save UploadPost credentials.');
    } finally {
      setUploadPostBusy(false);
    }
  }, [authHeaders, clientId, oauthStatusUrl, refresh, uploadPostInput, uploadPostUserInput]);

  // Detect oauth_success query param (set by oauth-callback redirect)
  // If this is a popup window, auto-close it. Either way, refresh statuses.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const oauthSuccess = params.get('oauth_success');
    if (!oauthSuccess) return;

    // Clean the URL (remove query params without reload)
    const cleanUrl = window.location.pathname;
    window.history.replaceState({}, '', cleanUrl);

    // Refresh platform statuses
    refresh();

    // If this is a popup window, close it after a brief delay
    // The parent window's setInterval will detect w.closed and call onRefresh()
    if (window.opener || window.history.length <= 2) {
      setTimeout(() => {
        window.close();
      }, 1500);
    }
  }, []);

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
      {oauthError && <div className="sc-error">{oauthError}</div>}

      {loading ? <div className="sc-loading"><div className="sc-spinner" />Loading…</div> : <>
        {/* Social Platforms */}
        <div className="sc-section-label">Social Platforms</div>
        <p className="sc-subtitle">Connect the socials you actually use — skip the ones you do not use. You can add more later.</p>
        <div className="sc-list">
          {sortedPlatforms.map((p, i) => (
            <PlatformRow key={p.platform} p={p} clientId={clientId} supabaseUrl={supabaseUrl} businessName={businessName} i={i} onDisconnect={disconnectPlatform} onRefresh={refresh} onStartOAuth={startOAuth} oauthBusy={oauthBusy} />
          ))}
        </div>

        {/* API Posting Proxy */}
        {allowPublisherProxyConfig && (
          <>
            <div className="sc-section-label" style={{ marginTop: 24 }}>API Posting Proxy</div>
            <p className="sc-subtitle">UploadPost enables temporary proxy posting to Facebook, Instagram, and TikTok.</p>
            <div className="sc-list">
              <div className={`sc-row ${uploadPostStatus.ready ? 'sc-row-connected' : ''}`}>
                <div className="sc-row-main">
                  <div className="sc-icon sc-icon-connector"><ConnectorIcon type="uploadpost" /></div>
                  <div className="sc-info">
                    <div className="sc-name">UploadPost</div>
                    <div className="sc-note">Covers Facebook, Instagram, and TikTok</div>
                  </div>
                  <div className="sc-actions">
                    <span className={`sc-badge ${uploadPostStatus.ready ? 'sc-badge-green' : 'sc-badge-red'}`}>
                      {uploadPostStatus.ready ? 'Active' : 'Not configured'}
                    </span>
                    {uploadPostStatus.ready && (
                      <>
                        <button className="sc-btn sc-btn-ghost" onClick={() => setShowUploadPostForm(v => !v)} disabled={uploadPostBusy}>
                          {showUploadPostForm ? 'Cancel' : 'Update'}
                        </button>
                        <button className="sc-btn sc-btn-ghost" onClick={() => saveUploadPostKey(true)} disabled={uploadPostBusy}>Remove</button>
                      </>
                    )}
                  </div>
                </div>
                {(!uploadPostStatus.ready || showUploadPostForm) && (
                  <div className="sc-token-row sc-row-support-form">
                    <input
                      className="sc-input"
                      type="password"
                      placeholder="UploadPost API key"
                      value={uploadPostInput}
                      onChange={e => setUploadPostInput(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && saveUploadPostKey(false)}
                    />
                    <input
                      className="sc-input"
                      type="text"
                      placeholder="UploadPost user/account"
                      value={uploadPostUserInput}
                      onChange={e => setUploadPostUserInput(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && saveUploadPostKey(false)}
                    />
                    <button className="sc-btn sc-btn-primary" onClick={() => saveUploadPostKey(false)} disabled={uploadPostBusy || !uploadPostInput || !uploadPostUserInput}>
                      {uploadPostBusy ? 'Saving...' : uploadPostStatus.ready ? 'Update' : 'Save'}
                    </button>
                  </div>
                )}
                {!uploadPostStatus.ready && !showUploadPostForm && (
                  <div className="sc-note sc-row-support-note">
                    Missing: {[!uploadPostStatus.hasKey && 'API key', !uploadPostStatus.hasUser && 'user/account'].filter(Boolean).join(', ')}
                  </div>
                )}
                {uploadPostError && <div className="sc-row-error sc-row-support-note">{uploadPostError}</div>}
              </div>
            </div>
          </>
        )}

        {/* Photo Feed Sources */}
        {photoConnectors.length > 0 && <>
          <div className="sc-section-label" style={{ marginTop: 24 }}>Photo Feed Sources</div>
          <p className="sc-subtitle">Connect where your team takes job photos. Connect as many as you use.</p>
          <div className="sc-list">
            {photoConnectors.map(c => (
              <ConnectorRow key={c.connector_type} c={c} clientId={clientId} endpoint={connectorStatusUrl} getToken={getToken} onRefresh={refresh} onStartOAuth={startOAuth} oauthBusy={oauthBusy} />
            ))}
          </div>
        </>}

        {/* Customer Data Sources */}
        {crmConnectors.length > 0 && <>
          <div className="sc-section-label" style={{ marginTop: 24 }}>Customer Data Sources</div>
          <p className="sc-subtitle">Connect your CRM to enrich outreach with real customer data.</p>
          <div className="sc-list">
            {crmConnectors.map(c => (
              <ConnectorRow key={c.connector_type} c={c} clientId={clientId} endpoint={connectorStatusUrl} getToken={getToken} onRefresh={refresh} onStartOAuth={startOAuth} oauthBusy={oauthBusy} />
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

function PlatformRow({ p, clientId, supabaseUrl, businessName, i, onDisconnect, onRefresh, onStartOAuth, oauthBusy }) {
  // Listen for OAuth success — postMessage (primary) + localStorage (fallback for when window.opener is null after redirects)
  useEffect(() => {
    function handleOAuthMessage(event) {
      const allowedOrigins = ['https://oyyfpkpzalhxztpcdjgq.supabase.co', 'http://localhost:54321'];
      if (!allowedOrigins.some(o => event.origin.startsWith(o) || event.origin === window.location.origin)) return;
      if (event.data?.type === 'oauth-success' && event.data?.platform === p.platform) {
        console.log(`[ConnectPanel] OAuth success for ${p.platform} via postMessage — refreshing`);
        if (onRefresh) onRefresh();
      }
    }
    function handleStorageEvent(event) {
      if (event.key === 'oauth-success') {
        try {
          const data = JSON.parse(event.newValue || '{}');
          if (data.platform === p.platform) {
            console.log(`[ConnectPanel] OAuth success for ${p.platform} via localStorage — refreshing`);
            if (onRefresh) onRefresh();
          }
        } catch {}
      }
    }
    window.addEventListener('message', handleOAuthMessage);
    window.addEventListener('storage', handleStorageEvent);
    return () => {
      window.removeEventListener('message', handleOAuthMessage);
      window.removeEventListener('storage', handleStorageEvent);
    };
  }, [p.platform, onRefresh]);

  const [showEmbed, setShowEmbed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  const [showOrgPicker, setShowOrgPicker] = useState(false);
  const [selectingOrg, setSelectingOrg] = useState(false);
  const [orgMismatchWarning, setOrgMismatchWarning] = useState(null);
  const [pendingOrg, setPendingOrg] = useState(null);
  const [showGoogleWarning, setShowGoogleWarning] = useState(false);
  const meta = PLATFORM_META[p.platform];
  if (!meta) return null;

  const isWebsite = p.platform === 'website';
  const isGoogleOAuth = ['youtube', 'gbp', 'google'].includes(p.platform);

  const openOAuthPopup = () => {
    if (onStartOAuth) onStartOAuth(p.platform);
  };
  const handleConnectClick = () => {
    if (isGoogleOAuth) { setShowGoogleWarning(true); } else { openOAuthPopup(); }
  };
  const details = p.details || {};

  // LinkedIn-specific state
  const isLinkedIn = p.platform === 'linkedin';
  const liAvailableOrgs = details.available_orgs || [];
  const liCurrentOrgUrn = details.org_urn;
  const liCurrentOrgName = currentLinkedInOrgName(details) || '';
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
    action = !meta.noOAuth && <button className="sc-btn sc-btn-warn" onClick={handleConnectClick} disabled={oauthBusy}>Reconnect</button>;
  } else if (!p.enabled) {
    statusBadge = <span className="sc-badge sc-badge-off">Disabled</span>;
  } else if (isLinkedIn && liNeedsOrgSelection) {
    statusBadge = <span className="sc-badge sc-badge-amber">Select Page</span>;
    action = <button className="sc-btn sc-btn-primary" onClick={() => setShowOrgPicker(!showOrgPicker)}>{showOrgPicker ? 'Cancel' : 'Choose Page'}</button>;
  } else {
    statusBadge = <span className="sc-badge sc-badge-red">Not connected</span>;
    if (isWebsite) action = <button className="sc-btn sc-btn-primary" onClick={() => setShowEmbed(!showEmbed)}>Get embed code</button>;
    else if (meta.noOAuth) action = meta.derived ? <span className="sc-badge sc-badge-off">Connect Facebook first</span> : null;
    else action = <button className="sc-btn sc-btn-primary" onClick={handleConnectClick} disabled={oauthBusy}>Connect</button>;
  }

  // LinkedIn detail note
  let linkedInNote = null;
  if (isLinkedIn) {
    if (p.connected && !p.is_expired && liCurrentOrgName) {
      linkedInNote = liCurrentOrgName;
    } else if (liNeedsOrgSelection) {
      linkedInNote = 'Authorized — select a LinkedIn page to post to';
    }
  }

  const accountNote = formatPlatformAccountLabel(p.platform, details);
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
                ? (accountNote || 'Connected')
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

      {/* Google OAuth unverified app warning — rendered via portal to escape sc-row overflow:hidden */}
      {showGoogleWarning && ReactDOM.createPortal(
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999, backdropFilter: 'blur(4px)' }} onClick={() => setShowGoogleWarning(false)}>
          <div style={{ background: 'var(--bg-card, #1a1a2e)', border: '1px solid var(--border, #333)', borderRadius: 16, padding: '32px 28px', maxWidth: 480, width: '90%', textAlign: 'center', boxShadow: '0 16px 48px rgba(0,0,0,0.5)' }} onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: 28, marginBottom: 12 }}>⚠️</div>
            <h3 style={{ margin: '0 0 12px', fontSize: 16, color: 'var(--slate-100, #f1f5f9)' }}>
              Google Verification Pending
            </h3>
            <p style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--slate-300, #cbd5e1)', margin: '0 0 12px' }}>
              Our Google OAuth app verification is currently pending with Google. When
              you connect, Google will show a warning that says <strong style={{ color: 'var(--slate-100, #f1f5f9)' }}>"Google hasn't verified this app"</strong>.
            </p>
            <p style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--slate-300, #cbd5e1)', margin: '0 0 12px' }}>
              This is expected and safe. To proceed:
            </p>
            <ol style={{ fontSize: 13, lineHeight: 1.8, color: 'var(--slate-200, #e2e8f0)', margin: '0 0 16px', paddingLeft: 20, textAlign: 'left' }}>
              <li>Click <strong>"Advanced"</strong> (bottom-left of the warning)</li>
              <li>Click <strong>"Go to Scale Small AI (unsafe)"</strong></li>
              <li>Review and grant the requested permissions</li>
            </ol>
            <p style={{ fontSize: 12, color: 'var(--slate-400, #94a3b8)', margin: '0 0 20px' }}>
              This warning will be removed once Google completes their verification review.
            </p>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
              <button className="sc-btn sc-btn-primary" onClick={() => { setShowGoogleWarning(false); openOAuthPopup(); }}>
                I Understand — Continue
              </button>
              <button className="sc-btn sc-btn-ghost" onClick={() => setShowGoogleWarning(false)}>Cancel</button>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}

async function connectorHeaders(getToken) {
  const token = getToken ? await getToken() : null;
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

function ConnectorRow({ c, clientId, endpoint, getToken, onRefresh, onStartOAuth, oauthBusy }) {
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const isConnected = c.status === 'connected';
  const needsDesignator = c.status === 'needs_designator';
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
      const res = await fetch(endpoint, { method: 'POST', headers: await connectorHeaders(getToken), body: JSON.stringify(body) });
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
      await fetch(endpoint, { method: 'POST', headers: await connectorHeaders(getToken), body: JSON.stringify({ connector_type: c.connector_type, client_id: clientId, action: 'disconnect' }) });
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
          <span className={`sc-badge ${isConnected ? 'sc-badge-green' : needsDesignator ? 'sc-badge-red' : 'sc-badge-amber'}`}>{isConnected ? 'Connected' : needsDesignator ? 'Action Required' : 'Setup Required'}</span>
          {isConnected && <button className="sc-btn sc-btn-danger" onClick={handleDisconnect} disabled={loading}>Disconnect</button>}
          {!isConnected && !needsDesignator && c.auth_type === 'oauth' && (
            <button className="sc-btn sc-btn-primary" onClick={() => onStartOAuth && onStartOAuth(c.connector_type)} disabled={loading || oauthBusy}>
              {oauthBusy ? 'Opening...' : `Connect ${c.display_name}`}
            </button>
          )}
        </div>
      </div>
      {needsDesignator && (
        <div className="sc-setup sc-setup-warning">
          <div style={{fontWeight:600,color:'var(--red)',marginBottom:8}}>⚠ Before &amp; After tags not found</div>
          <p style={{fontSize:13,color:'var(--slate-300)',marginBottom:12,lineHeight:1.5}}>
            Your CompanyCam account is connected, but no Before &amp; After tags were found. 
            Only photos tagged with <strong>Before</strong> or <strong>After</strong> are imported — this is required and cannot be changed.
          </p>
          <p style={{fontSize:13,color:'var(--slate-400)',marginBottom:12}}>
            Go to <strong>CompanyCam → Settings → Tags</strong> and create tags named <em>Before</em> and <em>After</em>. 
            Then reconnect below to activate photo ingestion.
          </p>
          <div className="sc-token-row">
            <input type="password" placeholder="Re-enter your API token to activate" value={token} onChange={e => setToken(e.target.value)} className="sc-input" />
            <button className="sc-btn sc-btn-primary" onClick={handleConnect} disabled={loading}>{loading ? 'Checking...' : 'Activate'}</button>
          </div>
          {error && <div className="sc-row-error">{error}</div>}
        </div>
      )}
      {!isConnected && !needsDesignator && c.auth_type === 'api_key' && (
        <div className="sc-setup">
          {c.setup_instructions?.steps && <ol className="sc-steps">{c.setup_instructions.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>}
          <div className="sc-token-row">
            <input type="password" placeholder="Paste your API token" value={token} onChange={e => setToken(e.target.value)} className="sc-input" />
            <button className="sc-btn sc-btn-primary" onClick={handleConnect} disabled={loading}>{loading ? 'Connecting...' : 'Connect'}</button>
          </div>
          {error && <div className="sc-row-error">{error}</div>}
        </div>
      )}
      {!isConnected && !needsDesignator && c.auth_type === 'oauth' && (
        <div className="sc-setup">
          {c.setup_instructions?.steps && <ol className="sc-steps">{c.setup_instructions.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>}
          {error && <div className="sc-row-error">{error}</div>}
        </div>
      )}
    </div>
  );
}

export { PlatformRow, ConnectorRow };
