import React, { useState, useEffect, useCallback } from 'react';
import ServiceIcon from './ServiceIcon.jsx';

export default function DataSourcePanel({ supabaseUrl, getToken }) {
  const [sources, setSources] = useState([]);
  const [consentText, setConsentText] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showConsent, setShowConsent] = useState(null);
  const [showSetup, setShowSetup] = useState(null);
  const [apiKey, setApiKey] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [success, setSuccess] = useState(null);

  const endpoint = `${supabaseUrl}/functions/v1/rr-data-sources`;

  const callApi = useCallback(async (method, body) => {
    const token = await getToken();
    const opts = { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` } };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(endpoint, opts);
    return res.json();
  }, [endpoint, getToken]);

  const loadSources = useCallback(async () => {
    try {
      const data = await callApi('GET');
      setSources(data.sources || []);
      setConsentText(data.consent_text || '');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, [callApi]);

  useEffect(() => { loadSources(); }, [loadSources]);

  const handleConsent = async (sourceType) => {
    setActionLoading(true); setError(null); setSuccess(null);
    try {
      const data = await callApi('POST', { action: 'give_consent', source_type: sourceType, consent_accepted: true });
      if (data.error) throw new Error(data.error);
      setShowConsent(null);
      await loadSources();
      setShowSetup(sourceType);
      setSuccess('Consent recorded. You can now connect this data source.');
    } catch (e) { setError(e.message); }
    finally { setActionLoading(false); }
  };

  const handleConnect = async (sourceType, authType) => {
    setActionLoading(true); setError(null); setSuccess(null);
    try {
      const body = { action: 'connect', source_type: sourceType };
      if (authType === 'api_key') {
        if (!apiKey.trim()) { setError('Enter your API key'); setActionLoading(false); return; }
        body.api_key = apiKey.trim();
      }
      const data = await callApi('POST', body);
      if (data.error) throw new Error(data.error);
      if (data.oauth_url) { window.location.href = data.oauth_url; return; }
      setApiKey('');
      setShowSetup(null);
      setSuccess(data.message || 'Connected!');
      await loadSources();
    } catch (e) { setError(e.message); }
    finally { setActionLoading(false); }
  };

  const handleDisconnect = async (sourceType) => {
    if (!confirm('Disconnect this data source? Existing imported data is preserved.')) return;
    setActionLoading(true); setError(null);
    try {
      await callApi('POST', { action: 'disconnect', source_type: sourceType });
      setSuccess('Data source disconnected.');
      await loadSources();
    } catch (e) { setError(e.message); }
    finally { setActionLoading(false); }
  };

  if (loading) return <div className="sc-loading"><div className="sc-spinner" />Loading data sources…</div>;

  const connected = sources.filter(s => s.connection_status === 'connected');
  const available = sources.filter(s => s.connection_status !== 'connected');

  return (
    <div className="sc-ds-section">
      <div className="sc-section-label">Customer Data Sources</div>
      <p className="sc-subtitle">Connect the tools you already use to run your business — your CRM, invoicing app, or field service software. Connect as many or as few as you use. <strong>If you only use one, that's perfect.</strong> <span className="sc-optional-badge">Optional</span></p>
      <p className="sc-note" style={{ marginBottom: 16, fontSize: 12, lineHeight: 1.5 }}>
        Your customer data is used exclusively to power your outreach system.
        We never sell, share, or use individual customer information for any other purpose.
      </p>

      {error && <div className="sc-row-error" style={{ marginBottom: 12 }}>{error}</div>}
      {success && <div className="sc-success" style={{ marginBottom: 12 }}>{success}</div>}

      {/* Connected */}
      {connected.length > 0 && (
        <div className="sc-list">
          {connected.map(s => (
            <div key={s.source_type} className="sc-row sc-row-connected">
              <div className="sc-row-main">
                <div className="sc-icon sc-icon-connector"><ServiceIcon type={s.source_type} /></div>
                <div className="sc-info">
                  <div className="sc-name">{s.display_name}</div>
                  <div className="sc-note">
                    {s.total_customers_imported > 0
                      ? `${s.total_customers_imported} customers · ${s.total_jobs_imported} jobs imported`
                      : 'Connected — sync will begin shortly'}
                    {s.last_sync_at && ` · Last sync: ${new Date(s.last_sync_at).toLocaleDateString()}`}
                  </div>
                </div>
                <div className="sc-actions">
                  <span className="sc-badge sc-badge-green">Connected</span>
                  <button className="sc-btn sc-btn-ghost" onClick={() => handleDisconnect(s.source_type)} disabled={actionLoading}>Disconnect</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Available (live + coming soon) */}
      {available.length > 0 && (
        <div className="sc-list" style={{ marginTop: connected.length > 0 ? 16 : 0 }}>
          {available.map(s => {
            const isComingSoon = s.availability_status === 'coming_soon';
            return (
              <div key={s.source_type} className={`sc-row${isComingSoon ? ' sc-row-coming-soon' : ''}`}>
                <div className="sc-row-main">
                  <div className="sc-icon sc-icon-connector"><ServiceIcon type={s.source_type} /></div>
                  <div className="sc-info">
                    <div className="sc-name">{s.display_name}</div>
                    <div className="sc-note">{s.description}</div>
                    {s.data_provided && !isComingSoon && (
                      <div className="sc-note" style={{ marginTop: 2 }}>
                        Provides: {s.data_provided.join(', ')}
                      </div>
                    )}
                  </div>
                  <div className="sc-actions">
                    {isComingSoon ? (
                      <span className="sc-badge sc-badge-coming-soon">Coming Soon</span>
                    ) : (
                      <>
                        {s.connection_status === 'disconnected' && <span className="sc-badge sc-badge-off">Disconnected</span>}
                        {s.connection_status === 'error' && <span className="sc-badge sc-badge-red">Error</span>}
                        {s.data_consent_given ? (
                          <button className="sc-btn sc-btn-primary" onClick={() => setShowSetup(s.source_type)} disabled={actionLoading}>
                            {s.connection_status === 'disconnected' ? 'Reconnect' : 'Connect'}
                          </button>
                        ) : (
                          <button className="sc-btn sc-btn-primary" onClick={() => setShowConsent(s.source_type)} disabled={actionLoading}>Connect</button>
                        )}
                      </>
                    )}
                  </div>
                </div>

                {/* Consent */}
                {!isComingSoon && showConsent === s.source_type && (
                  <div className="sc-consent">
                    <div className="sc-consent-header">Data use disclosure</div>
                    <div className="sc-consent-body">{consentText}</div>
                    <div className="sc-consent-actions">
                      <button className="sc-btn sc-btn-ghost" onClick={() => setShowConsent(null)}>Cancel</button>
                      <button className="sc-btn sc-btn-primary" onClick={() => handleConsent(s.source_type)} disabled={actionLoading}>
                        {actionLoading ? 'Saving...' : 'I accept — continue'}
                      </button>
                    </div>
                  </div>
                )}

                {/* Setup */}
                {!isComingSoon && showSetup === s.source_type && s.data_consent_given && (
                  <div className="sc-setup">
                    {s.setup_instructions?.steps && (
                      <ol className="sc-steps">
                        {s.setup_instructions.steps.map((step, i) => <li key={i}>{step}</li>)}
                      </ol>
                    )}
                    {s.auth_type === 'api_key' && (
                      <div className="sc-token-row">
                        <input type="password" placeholder="Paste your API key" value={apiKey} onChange={e => setApiKey(e.target.value)} className="sc-input" />
                        <button className="sc-btn sc-btn-primary" onClick={() => handleConnect(s.source_type, 'api_key')} disabled={actionLoading}>
                          {actionLoading ? 'Connecting...' : 'Connect'}
                        </button>
                      </div>
                    )}
                    {s.auth_type === 'oauth' && (
                      <button className="sc-btn sc-btn-primary" onClick={() => handleConnect(s.source_type, 'oauth')} disabled={actionLoading}>
                        {actionLoading ? 'Redirecting...' : `Connect ${s.display_name}`}
                      </button>
                    )}
                    {s.auth_type === 'webhook' && (
                      <button className="sc-btn sc-btn-primary" onClick={() => handleConnect(s.source_type, 'webhook')} disabled={actionLoading}>
                        {actionLoading ? 'Activating...' : 'Activate webhook'}
                      </button>
                    )}
                    {s.auth_type === 'csv' && <p className="sc-note">CSV upload available under Repeat & Referral → Customers.</p>}
                    {s.auth_type === 'manual' && <p className="sc-note">Add customers manually under Repeat & Referral → Customers.</p>}
                    {s.error_message && <div className="sc-row-error">{s.error_message}</div>}
                    <button className="sc-btn sc-btn-ghost" onClick={() => { setShowSetup(null); setApiKey(''); }} style={{ marginTop: 8 }}>Cancel</button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
