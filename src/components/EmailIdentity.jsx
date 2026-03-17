import React, { useState, useEffect, useCallback } from 'react';

const PROVIDERS = [
  { id: 'godaddy', name: 'GoDaddy', helpUrl: 'https://www.godaddy.com/help/invite-a-delegate-to-access-my-godaddy-account-12376', accessType: 'Delegate Access', accessLevel: 'Products & Domains', steps: ['Log in at godaddy.com', 'Click your name (top-right) → Account Settings', 'Select "Delegate Access" from the menu', 'Click "Invite to Access"', 'Enter name: ScaleSmall, email: admin@scalesmall.ai', 'Select "Products & Domains" as access level', 'Click Invite'] },
  { id: 'namecheap', name: 'Namecheap', helpUrl: 'https://www.namecheap.com/support/knowledgebase/article.aspx/9925/83/how-to-share-access-to-a-domain/', accessType: 'Share Access', accessLevel: 'Domain management', steps: ['Log in at namecheap.com', 'Go to Domain List → click Manage on your domain', 'Click the "Sharing & Transfer" tab', 'Click "Add New User"', 'Enter: admin@scalesmall.ai', 'Grant DNS management permissions', 'Click Share'] },
  { id: 'cloudflare', name: 'Cloudflare', helpUrl: 'https://developers.cloudflare.com/fundamentals/manage-members/manage/', accessType: 'Account Member', accessLevel: 'Administrator', steps: ['Log in at dash.cloudflare.com', 'Click "Manage Account" → Members', 'Click "Invite"', 'Enter: admin@scalesmall.ai', 'Set scope to your domain, Role: Administrator', 'Click "Continue to summary" then "Invite"'] },
  { id: 'squarespace', name: 'Squarespace Domains', helpUrl: 'https://support.squarespace.com/hc/en-us/articles/205812378', accessType: 'Contributor', accessLevel: 'Domain management', steps: ['Log in at domains.squarespace.com', 'Select your domain', 'Go to Settings → Permissions', 'Click "Invite contributor"', 'Enter: admin@scalesmall.ai', 'Click Send'] },
  { id: 'bluehost', name: 'Bluehost', helpUrl: 'https://www.bluehost.com/help/article/manage-users', accessType: 'Account Access', accessLevel: 'Domain manager', steps: ['Log in to your Bluehost dashboard', 'Go to Advanced → Zone Editor', 'Or: contact Bluehost support to request DNS delegate access for admin@scalesmall.ai'] },
  { id: 'hostinger', name: 'Hostinger', helpUrl: 'https://support.hostinger.com/en/articles/1696781-how-to-edit-dns-zone', accessType: 'Account Sharing', accessLevel: 'DNS management', steps: ['Log in at hpanel.hostinger.com', 'Go to Account → Account Sharing', 'Click "Invite"', 'Enter: admin@scalesmall.ai', 'Select access to your domain', 'Click Send'] },
  { id: 'ionos', name: 'IONOS (1&1)', helpUrl: 'https://www.ionos.com/help/domains/dns-settings/', accessType: 'Admin Access', accessLevel: 'DNS management', steps: ['Log in at my.ionos.com', 'Go to Domains → your domain → DNS Settings', 'Contact IONOS support to add admin@scalesmall.ai as authorized user for DNS'] },
  { id: 'hover', name: 'Hover', helpUrl: 'https://help.hover.com/hc/en-us/articles/217282457', accessType: 'Shared Access', accessLevel: 'DNS management', steps: ['Log in at hover.com', 'Go to Account → Shared Access', 'Click "Add a shared user"', 'Enter: admin@scalesmall.ai', 'Grant DNS editing permissions'] },
  { id: 'networksolutions', name: 'Network Solutions', helpUrl: 'https://www.networksolutions.com/support/', accessType: 'Account Contact', accessLevel: 'Technical Contact', steps: ['Log in at networksolutions.com', 'Go to Account Settings → Account Contacts', 'Add admin@scalesmall.ai as Technical Contact', 'This grants DNS management access'] },
  { id: 'other', name: "Other / I don't know", helpUrl: null, accessType: 'DNS admin access', accessLevel: 'DNS management', steps: ['Log in to wherever you bought your domain', 'Look for: "Delegate Access", "Team Members", "Account Sharing", or "User Management"', 'Invite admin@scalesmall.ai with DNS management permissions', "If you can't find it, contact your provider's support", "Not sure who your provider is? Email support@scalesmall.ai"] },
];

// Copy-to-clipboard helper with visual feedback
function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button className="sc-dns-copy" onClick={handleCopy} title="Copy to clipboard">
      {copied ? '✓' : '⧉'}
    </button>
  );
}

// DNS records table with per-cell copy buttons
function DnsRecordsTable({ records }) {
  if (!records || records.length === 0) return null;
  return (
    <div className="sc-dns-records">
      <p className="sc-dns-label">Add these DNS records at your domain registrar:</p>
      <table className="sc-dns-table">
        <thead><tr><th>Type</th><th>Name</th><th>Value</th><th></th></tr></thead>
        <tbody>
          {records.map((r, i) => {
            const type = r.type || r.record_type || '';
            const name = r.name || r.host || '';
            const value = r.value || r.data || '';
            return (
              <tr key={i}>
                <td className="sc-dns-type">{type}</td>
                <td className="sc-dns-name">{name} <CopyBtn text={name} /></td>
                <td className="sc-dns-val">{value} <CopyBtn text={value} /></td>
                <td className="sc-dns-copy-all"><button className="sc-dns-copy-row" onClick={() => navigator.clipboard.writeText(`${type}\t${name}\t${value}`)} title="Copy entire row">Copy row</button></td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="sc-dns-hint">DNS changes can take up to 48 hours to propagate. Click the ⧉ icon next to any value to copy it.</p>
    </div>
  );
}

export default function EmailIdentity({ supabaseUrl, getToken, stripePublishableKey }) {
  const [domain, setDomain] = useState(null);
  const [status, setStatus] = useState('loading');
  const [records, setRecords] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [showExplainer, setShowExplainer] = useState(true);
  const [showDIFY, setShowDIFY] = useState(false);
  const [difyStep, setDifyStep] = useState('select_provider'); // select_provider → pay → instructions → done
  const [selectedProvider, setSelectedProvider] = useState(null);
  const [showSelfSetup, setShowSelfSetup] = useState(false);
  const [paymentProcessing, setPaymentProcessing] = useState(false);

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
      if (data.status && data.status !== 'not_started') {
        setShowExplainer(false);
        setAcknowledged(true);
      }
    } catch { setStatus('not_started'); }
  }, [callApi]);

  useEffect(() => { loadStatus(); }, [loadStatus]);

  const handleAddDomain = async () => {
    if (!input.trim()) return;
    setLoading(true); setError(null); setSuccess(null);
    try {
      const data = await callApi('add_domain', { domain: input.trim() });
      if (data.error) throw new Error(data.error);
      setDomain(data.domain); setStatus('pending_dns');
      setRecords(data.records || []); setInput('');
      setSuccess('Domain registered. Copy the DNS records below and add them to your domain provider, then click Verify.');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const handleVerify = async () => {
    setLoading(true); setError(null); setSuccess(null);
    try {
      const data = await callApi('verify');
      if (data.error) throw new Error(data.error);
      setStatus(data.status);
      setSuccess(data.status === 'verified'
        ? 'Domain verified! Emails will now send directly from your domain.'
        : 'DNS records not yet detected. This can take up to 48 hours.');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const handleRemove = async () => {
    if (!confirm('Remove domain verification? Emails will send from the shared ScaleSmall domain.')) return;
    setLoading(true); setError(null);
    try {
      await callApi('remove_domain');
      setDomain(null); setStatus('not_started'); setRecords([]);
      setSuccess('Domain removed.'); setShowExplainer(true); setAcknowledged(false);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  // DIFY Stripe payment
  const handleDIFYPayment = async () => {
    setPaymentProcessing(true); setError(null);
    try {
      const token = await getToken();
      const res = await fetch(`${supabaseUrl}/functions/v1/stripe-checkout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          service_slug: 'email_domain_setup',
          success_url: window.location.href + '?dify_paid=true',
          cancel_url: window.location.href + '?dify_cancelled=true',
        }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      if (data.url) {
        window.location.href = data.url; // Redirect to Stripe Checkout
      } else {
        throw new Error('No checkout URL returned');
      }
    } catch (e) {
      setError('Payment setup failed: ' + e.message + '. Please try again or contact support.');
      setPaymentProcessing(false);
    }
  };

  // Check for payment return
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('dify_paid') === 'true') {
      setAcknowledged(true); setShowExplainer(false);
      setShowDIFY(true); setDifyStep('instructions');
      setSuccess('Payment received! Now follow the steps below to grant us access.');
      // Clean URL
      const url = new URL(window.location);
      url.searchParams.delete('dify_paid');
      window.history.replaceState({}, '', url);
    }
    if (params.get('dify_cancelled') === 'true') {
      setAcknowledged(true); setShowExplainer(false);
      setShowDIFY(true); setDifyStep('select_provider');
      const url = new URL(window.location);
      url.searchParams.delete('dify_cancelled');
      window.history.replaceState({}, '', url);
    }
  }, []);

  const providerInfo = selectedProvider ? PROVIDERS.find(p => p.id === selectedProvider) : null;

  return (
    <div className="sc-ei-section">
      <div className="sc-section-label">Email identity</div>

      {/* EXPLAINER */}
      {showExplainer && !acknowledged && status === 'not_started' && (
        <div className="sc-ei-explainer">
          <div className="sc-ei-explainer-card">
            <h3 className="sc-ei-h3">How your outreach emails work</h3>
            <p className="sc-ei-text">When we send automated follow-ups, review requests, and referral asks to your customers, the emails need a sender identity. You have two options:</p>
            <div className="sc-ei-options">
              <div className="sc-ei-option">
                <div className="sc-ei-option-icon">✉️</div>
                <div className="sc-ei-option-label">Verify your domain (recommended)</div>
                <div className="sc-ei-option-desc">Emails send from <strong>your email address</strong> (e.g., info@yourbusiness.com). Customers see your name, your domain. Best for trust and deliverability.</div>
              </div>
              <div className="sc-ei-option sc-ei-option-alt">
                <div className="sc-ei-option-icon">🔄</div>
                <div className="sc-ei-option-label">Use shared domain (default)</div>
                <div className="sc-ei-option-desc">Emails send as <strong>"Your Business Name"</strong> from mail.scalesmall.ai. Customers see your name but our domain. Replies still go to you. Works immediately.</div>
              </div>
            </div>
            <p className="sc-ei-text" style={{ marginTop: 12, fontSize: 12, color: '#94a3b8' }}>You can always change this later. If you skip, outreach uses the shared domain automatically.</p>
            <button className="sc-btn sc-btn-primary" onClick={() => { setAcknowledged(true); setShowExplainer(false); }} style={{ marginTop: 12 }}>Got it — set up my domain</button>
            <button className="sc-btn sc-btn-ghost" onClick={() => { setAcknowledged(true); setShowExplainer(false); }} style={{ marginTop: 8 }}>Skip for now</button>
          </div>
        </div>
      )}

      {/* MAIN SETUP */}
      {acknowledged && (<>
        {error && <div className="sc-row-error" style={{ marginBottom: 12 }}>{error}</div>}
        {success && <div className="sc-success" style={{ marginBottom: 12 }}>{success}</div>}

        {/* VERIFIED */}
        {status === 'verified' && (
          <div className="sc-row sc-row-connected">
            <div className="sc-row-main">
              <div className="sc-icon" style={{ background: '#10b981', color: '#fff' }}>✓</div>
              <div className="sc-info"><div className="sc-name">{domain}</div><div className="sc-note">Verified — emails send from your domain</div></div>
              <div className="sc-actions"><span className="sc-badge sc-badge-green">Verified</span><button className="sc-btn sc-btn-ghost" onClick={handleRemove} disabled={loading}>Remove</button></div>
            </div>
          </div>
        )}

        {/* PENDING DNS — shows copyable DNS records */}
        {status === 'pending_dns' && (
          <div className="sc-row">
            <div className="sc-row-main">
              <div className="sc-icon" style={{ background: '#f59e0b', color: '#fff' }}>⏳</div>
              <div className="sc-info"><div className="sc-name">{domain}</div><div className="sc-note">Add the DNS records below, then click Verify</div></div>
              <div className="sc-actions">
                <span className="sc-badge sc-badge-amber">Pending</span>
                <button className="sc-btn sc-btn-primary" onClick={handleVerify} disabled={loading}>{loading ? 'Checking...' : 'Verify DNS'}</button>
                <button className="sc-btn sc-btn-ghost" onClick={handleRemove} disabled={loading}>Remove</button>
              </div>
            </div>
            <DnsRecordsTable records={records} />
          </div>
        )}

        {/* NOT STARTED / FAILED — choice + flows */}
        {(status === 'not_started' || status === 'failed') && (<>
          <p className="sc-subtitle">Verify your domain so emails send from your address.</p>
          <div className="sc-ei-choice-row">
            <button className={`sc-ei-choice-btn ${showSelfSetup ? 'sc-ei-choice-active' : ''}`} onClick={() => { setShowSelfSetup(true); setShowDIFY(false); }}>
              <span className="sc-ei-choice-icon">🔧</span>
              <span className="sc-ei-choice-text"><strong>I'll set it up myself</strong><small>Free — enter your domain and add DNS records</small></span>
            </button>
            <button className={`sc-ei-choice-btn ${showDIFY ? 'sc-ei-choice-active' : ''}`} onClick={() => { setShowDIFY(true); setShowSelfSetup(false); setDifyStep('select_provider'); }}>
              <span className="sc-ei-choice-icon">🙋</span>
              <span className="sc-ei-choice-text"><strong>Do it for me — $50</strong><small>We handle the entire DNS setup for you</small></span>
            </button>
          </div>

          {/* SELF SETUP */}
          {showSelfSetup && (
            <div className="sc-row">
              <div className="sc-row-main"><div className="sc-icon sc-icon-connector">📧</div><div className="sc-info"><div className="sc-name">Custom email domain</div><div className="sc-note">{status === 'failed' ? 'Verification failed — try again' : 'Enter your business domain to get DNS records'}</div></div></div>
              <div className="sc-setup"><div className="sc-token-row"><input type="text" placeholder="yourbusiness.com" value={input} onChange={e => setInput(e.target.value)} className="sc-input" onKeyDown={e => e.key === 'Enter' && handleAddDomain()} /><button className="sc-btn sc-btn-primary" onClick={handleAddDomain} disabled={loading || !input.trim()}>{loading ? 'Adding...' : 'Get DNS records'}</button></div></div>
            </div>
          )}

          {/* DO IT FOR ME — Step 1: Select provider */}
          {showDIFY && difyStep === 'select_provider' && (
            <div className="sc-ei-dify">
              <div className="sc-ei-dify-card">
                <h4 className="sc-ei-h4">We'll set it up for you — $50 one-time</h4>
                <p className="sc-ei-text">We'll configure the DNS records on your domain so outreach emails send from your email address. You just need to grant us limited DNS access to your domain provider. <strong>We only touch DNS settings</strong> — never billing, transfers, or anything else.</p>
                <p className="sc-ei-text" style={{ fontWeight: 600, color: '#f1f5f9', marginTop: 12 }}>Step 1: Where is your domain registered?</p>
                <div className="sc-ei-provider-grid">
                  {PROVIDERS.map(p => (
                    <button key={p.id} className={`sc-ei-provider-btn ${selectedProvider === p.id ? 'sc-ei-provider-active' : ''}`} onClick={() => setSelectedProvider(p.id)}>{p.name}</button>
                  ))}
                </div>
                {selectedProvider && (
                  <button className="sc-btn sc-btn-primary" onClick={handleDIFYPayment} disabled={paymentProcessing} style={{ marginTop: 16 }}>
                    {paymentProcessing ? 'Redirecting to payment...' : 'Continue — Pay $50'}
                  </button>
                )}
                <button className="sc-btn sc-btn-ghost" onClick={() => { setShowDIFY(false); setSelectedProvider(null); }} style={{ marginTop: 8 }}>Cancel</button>
              </div>
            </div>
          )}

          {/* DO IT FOR ME — Step 2: After payment, show instructions */}
          {showDIFY && difyStep === 'instructions' && (
            <div className="sc-ei-dify">
              <div className="sc-ei-dify-card">
                <h4 className="sc-ei-h4">Step 2: Grant us DNS access</h4>
                <p className="sc-ei-text">Follow the steps for your domain provider to invite <code>admin@scalesmall.ai</code> with DNS management access. We'll handle everything else within 24 hours.</p>

                {!selectedProvider && (
                  <>
                    <p className="sc-ei-text" style={{ fontWeight: 600, color: '#f1f5f9' }}>Select your provider:</p>
                    <div className="sc-ei-provider-grid">
                      {PROVIDERS.map(p => (
                        <button key={p.id} className={`sc-ei-provider-btn ${selectedProvider === p.id ? 'sc-ei-provider-active' : ''}`} onClick={() => setSelectedProvider(p.id)}>{p.name}</button>
                      ))}
                    </div>
                  </>
                )}

                {providerInfo && (
                  <div className="sc-ei-provider-detail">
                    <h5 className="sc-ei-h5">Steps for {providerInfo.name}</h5>
                    <div className="sc-ei-provider-meta">
                      <span>Feature: <strong>{providerInfo.accessType}</strong></span>
                      <span>Level: <strong>{providerInfo.accessLevel}</strong></span>
                    </div>
                    <ol className="sc-ei-provider-steps">
                      {providerInfo.steps.map((step, i) => <li key={i}>{step}</li>)}
                    </ol>
                    {providerInfo.helpUrl && (
                      <a href={providerInfo.helpUrl} target="_blank" rel="noopener noreferrer" className="sc-ei-help-link">
                        📖 Official {providerInfo.name} guide with screenshots & video →
                      </a>
                    )}
                    <button className="sc-btn sc-btn-ghost" onClick={() => setSelectedProvider(null)} style={{ marginTop: 8, fontSize: 11 }}>Switch provider</button>
                  </div>
                )}

                <button className="sc-btn sc-btn-primary" onClick={() => { setDifyStep('done'); setSuccess("We'll accept the invite and configure DNS within 24 hours. Check back here for status."); }} disabled={!selectedProvider} style={{ marginTop: 16 }}>✓ I've invited admin@scalesmall.ai</button>
                <button className="sc-btn sc-btn-ghost" onClick={() => setShowDIFY(false)} style={{ marginTop: 8 }}>Cancel</button>
              </div>
            </div>
          )}

          {/* DO IT FOR ME — Done */}
          {showDIFY && difyStep === 'done' && (
            <div className="sc-row sc-row-connected">
              <div className="sc-row-main">
                <div className="sc-icon" style={{ background: '#3b82f6', color: '#fff' }}>🔧</div>
                <div className="sc-info"><div className="sc-name">Setup in progress</div><div className="sc-note">We'll accept the invite, add DNS records, and verify your domain within 24 hours.</div></div>
                <div className="sc-actions"><span className="sc-badge sc-badge-amber">In progress</span></div>
              </div>
            </div>
          )}
        </>)}
      </>)}
    </div>
  );
}
