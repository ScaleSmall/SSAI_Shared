import React, { useState, useEffect, useCallback } from 'react';

/**
 * Domain verification flow for per-client email sending.
 * Shows in ConnectPanel when R&R service is active.
 *
 * @param {string} supabaseUrl
 * @param {function} getToken - returns current session access token
 */
export default function EmailIdentity({ supabaseUrl, getToken }) {
  const [domain, setDomain] = useState(null);
  const [status, setStatus] = useState('loading');
  const [records, setRecords] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const endpoint = `${supabaseUrl}/functions/v1/rr-domain-verify`;

  const callApi = useCallback(async (action, extra = {}) => {
    const token = await getToken();
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ action, ...extra }),
    });
    return res.json();
  }, [endpoint, getToken]);

  const loadStatus = useCallback(async () => {
    try {
      const data = await callApi('get_records');
      setDomain(data.domain || null);
      setStatus(data.status || 'not_started');
      setRecords(data.records || []);
    } catch (e) {
      setStatus('not_started');
    }
  }, [callApi]);

  useEffect(() => { loadStatus(); }, [loadStatus]);

  const handleAddDomain = async () => {
    if (!input.trim()) return;
    setLoading(true); setError(null); setSuccess(null);
    try {
      const data = await callApi('add_domain', { domain: input.trim() });
      if (data.error) throw new Error(data.error);
      setDomain(data.domain);
      setStatus('pending_dns');
      setRecords(data.records || []);
      setInput('');
      setSuccess('Domain added. Add these DNS records to your domain provider:');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const handleVerify = async () => {
    setLoading(true); setError(null); setSuccess(null);
    try {
      const data = await callApi('verify');
      if (data.error) throw new Error(data.error);
      setStatus(data.status);
      if (data.status === 'verified') setSuccess('Domain verified! Emails will now send from your domain.');
      else setSuccess('DNS records not yet detected. This can take up to 48 hours.');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const handleRemove = async () => {
    if (!confirm('Remove domain verification? Emails will send from the shared ScaleSmall domain.')) return;
    setLoading(true); setError(null);
    try {
      await callApi('remove_domain');
      setDomain(null); setStatus('not_started'); setRecords([]);
      setSuccess('Domain removed.');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="sc-ei-section">
      <div className="sc-section-label">Email identity</div>
      <p className="sc-subtitle">
        Verify your domain so outreach emails send directly from your email address —
        customers see your business, not ScaleSmall.
      </p>

      {error && <div className="sc-row-error" style={{ marginBottom: 12 }}>{error}</div>}
      {success && <div className="sc-success" style={{ marginBottom: 12 }}>{success}</div>}

      {status === 'verified' && (
        <div className="sc-row sc-row-connected">
          <div className="sc-row-main">
            <div className="sc-icon" style={{ background: '#10b981', color: '#fff' }}>✓</div>
            <div className="sc-info">
              <div className="sc-name">{domain}</div>
              <div className="sc-note">Verified — emails send from your domain</div>
            </div>
            <div className="sc-actions">
              <span className="sc-badge sc-badge-green">Verified</span>
              <button className="sc-btn sc-btn-ghost" onClick={handleRemove} disabled={loading}>Remove</button>
            </div>
          </div>
        </div>
      )}

      {status === 'pending_dns' && (
        <div className="sc-row">
          <div className="sc-row-main">
            <div className="sc-icon" style={{ background: '#f59e0b', color: '#fff' }}>⏳</div>
            <div className="sc-info">
              <div className="sc-name">{domain}</div>
              <div className="sc-note">Waiting for DNS records</div>
            </div>
            <div className="sc-actions">
              <span className="sc-badge sc-badge-amber">Pending</span>
              <button className="sc-btn sc-btn-primary" onClick={handleVerify} disabled={loading}>
                {loading ? 'Checking...' : 'Verify DNS'}
              </button>
              <button className="sc-btn sc-btn-ghost" onClick={handleRemove} disabled={loading}>Remove</button>
            </div>
          </div>
          {records.length > 0 && (
            <div className="sc-dns-records">
              <p className="sc-dns-label">Add these DNS records at your domain registrar:</p>
              <table className="sc-dns-table">
                <thead><tr><th>Type</th><th>Name</th><th>Value</th></tr></thead>
                <tbody>
                  {records.map((r, i) => (
                    <tr key={i}>
                      <td className="sc-dns-type">{r.type || r.record_type}</td>
                      <td className="sc-dns-name">{r.name || r.host}</td>
                      <td className="sc-dns-val">{r.value || r.data}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="sc-dns-hint">DNS changes can take up to 48 hours to propagate.</p>
            </div>
          )}
        </div>
      )}

      {(status === 'not_started' || status === 'failed') && (
        <div className="sc-row">
          <div className="sc-row-main">
            <div className="sc-icon sc-icon-connector">📧</div>
            <div className="sc-info">
              <div className="sc-name">Custom email domain</div>
              <div className="sc-note">
                {status === 'failed' ? 'Verification failed — try again or use a different domain' :
                 'Send outreach from your own email domain (e.g., yourname@yourbusiness.com)'}
              </div>
            </div>
          </div>
          <div className="sc-setup">
            <div className="sc-token-row">
              <input
                type="text"
                placeholder="yourbusiness.com"
                value={input}
                onChange={e => setInput(e.target.value)}
                className="sc-input"
                onKeyDown={e => e.key === 'Enter' && handleAddDomain()}
              />
              <button className="sc-btn sc-btn-primary" onClick={handleAddDomain} disabled={loading || !input.trim()}>
                {loading ? 'Adding...' : 'Add domain'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
