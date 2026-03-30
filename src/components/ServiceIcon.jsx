import React from 'react';

/**
 * Brand icons for all connectors (photo sources) and data sources (CRMs, accounting, etc.).
 * Usage: <ServiceIcon type="companycam" /> or <ServiceIcon type="stripe" />
 * All icons are 20x20 rendered in a 24x24 viewBox with brand colors baked in.
 */

const icons = {

  // ─── Photo Feed Sources ───────────────────────────────────────────

  companycam: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0062FF"/>
      <path d="M19.5 8.5h-2.1l-1.3-2H7.9l-1.3 2H4.5A1.5 1.5 0 003 10v7.5A1.5 1.5 0 004.5 19h15a1.5 1.5 0 001.5-1.5V10a1.5 1.5 0 00-1.5-1.5zM12 16a3 3 0 110-6 3 3 0 010 6z" fill="#fff"/>
      <circle cx="12" cy="13" r="1.5" fill="#fff" opacity=".6"/>
    </svg>
  ),

  google_drive: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <path d="M8.6 2L2 13.6l3.2 5.4H19l3.2-5.4z" fill="#4285F4"/>
      <path d="M15.4 2H8.6l7.4 11.6h7.2z" fill="#34A853"/>
      <path d="M2 13.6L5.2 19H18.8l-3.4-5.4z" fill="#FBBC04"/>
      <path d="M8.6 2L12 7.8 15.4 2z" fill="#EA4335"/>
    </svg>
  ),

  dropbox: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0061FF"/>
      <path d="M12 5L7 8.2l5 3.2 5-3.2L12 5zM7 14.6L12 17.8l5-3.2-5-3.2-5 3.2zM7 8.2L2 11.4l5 3.2 5-3.2-5-3.2zM17 8.2l-5 3.2 5 3.2 5-3.2-5-3.2zM12 11.8l-5 3.2 5 3.2 5-3.2-5-3.2z" fill="#fff"/>
    </svg>
  ),

  onedrive: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0078D4"/>
      <path d="M4 14.5a3.5 3.5 0 013.5-3.5c.24 0 .47.02.7.07A4.5 4.5 0 0117 12.5a3 3 0 010 6H7a3 3 0 01-3-3z" fill="#fff"/>
      <path d="M13.5 9.5a3 3 0 00-2.83 2H11a4 4 0 014 4h2.5a2.5 2.5 0 000-5 3 3 0 00-4-3.27A3 3 0 0013.5 9.5z" fill="rgba(255,255,255,0.7)"/>
    </svg>
  ),

  box: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0061D5"/>
      <text x="12" y="16.5" textAnchor="middle" fontSize="11" fontWeight="700" fill="#fff" fontFamily="Arial,sans-serif">Box</text>
    </svg>
  ),

  procore: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#F07D23"/>
      <path d="M6 6h7a5 5 0 010 10H6V6zm3 3v4h4a2 2 0 000-4H9z" fill="#fff"/>
    </svg>
  ),

  buildertrend: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#E31937"/>
      <path d="M6 6h6.5a4 4 0 012.8 6.8A4 4 0 0113 18H6V6zm3 2.5v3h3.5a1.5 1.5 0 000-3H9zm0 5v3h4a1.5 1.5 0 000-3H9z" fill="#fff"/>
    </svg>
  ),

  houzz_pro: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#73BA21"/>
      <path d="M6 18V6h3v4.5h6V6h3v12h-3v-4.5H9V18H6z" fill="#fff"/>
    </svg>
  ),

  manual_upload: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#475569"/>
      <path d="M12 4l-5 5h3v5h4V9h3l-5-5zM7 17v2h10v-2H7z" fill="#fff"/>
    </svg>
  ),

  // ─── CRM / Field Service ──────────────────────────────────────────

  ghl: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#000"/>
      <path d="M12 3L4 7.5v4.5l8 4.5 8-4.5V7.5L12 3zm0 2.4l5.2 2.9L12 11.2 6.8 8.3 12 5.4zM4 13.5l8 4.5 8-4.5v1.8l-8 4.5-8-4.5V13.5z" fill="#C9F01E"/>
    </svg>
  ),

  paintscout: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#2563EB"/>
      <path d="M8 6h4a4 4 0 014 4 4 4 0 01-4 4H11v4H8V6zm3 2.5v3h1a1.5 1.5 0 000-3h-1z" fill="#fff"/>
      <circle cx="16.5" cy="17" r="1.5" fill="#93C5FD"/>
    </svg>
  ),

  quickbooks: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="11" fill="#2CA01C"/>
      <path d="M7 8.5A3.5 3.5 0 0110.5 5h.5v2h-.5a1.5 1.5 0 000 3h3a3.5 3.5 0 010 7H13v-2h.5a1.5 1.5 0 000-3h-3A3.5 3.5 0 017 8.5z" fill="#fff"/>
    </svg>
  ),

  jobber: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#7AC143"/>
      <path d="M13 5h3v9.5a4.5 4.5 0 01-9 0v-1h3v1a1.5 1.5 0 003 0V5z" fill="#fff"/>
    </svg>
  ),

  servicetitan: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0E1F3E"/>
      <path d="M5 8h14v2.5H13v8h-3v-8H5V8z" fill="#F5A623"/>
    </svg>
  ),

  housecall_pro: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0369A1"/>
      <path d="M12 4L4 11h2.5v7h4v-4h3v4h4v-7H20L12 4z" fill="#fff"/>
    </svg>
  ),

  square: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#000"/>
      <rect x="4" y="4" width="16" height="16" rx="2" fill="#fff"/>
      <rect x="8" y="8" width="8" height="8" rx="1" fill="#000"/>
    </svg>
  ),

  workiz: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#00B3E6"/>
      <path d="M4 7h3l2.5 6.5L12 7h2l2.5 6.5L19 7h3l-4 10h-2.5L15 11.5 12.5 17h-2.5z" fill="#fff"/>
    </svg>
  ),

  jobnimbus: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#F47821"/>
      <path d="M12 4L5 9.5v9.5h5v-5h4v5h5V9.5L12 4z" fill="#fff"/>
    </svg>
  ),

  acculynx: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#00A651"/>
      <path d="M12 4l7 14H5l7-14zm0 4.5L8.5 15h7L12 8.5z" fill="#fff"/>
    </svg>
  ),

  xero: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="11" fill="#1AB4D7"/>
      <path d="M7.5 7.5l4.5 4.5-4.5 4.5 1.5 1.5L13.5 13.5l4.5 4.5 1.5-1.5L15 12l4.5-4.5L18 6l-4.5 4.5L9 6z" fill="#fff"/>
    </svg>
  ),

  freshbooks: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#29AB6E"/>
      <path d="M7 6h6a3 3 0 010 6H10v2h3.5v2H10v2H7V6zm3 2.5v3h3a1.5 1.5 0 000-3h-3z" fill="#fff"/>
    </svg>
  ),

  stripe: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#635BFF"/>
      <path d="M11.5 9.5c0-1.1.9-1.5 2.4-1.5 2.1 0 4.1.6 4.1.6V5.5S16 5 13.5 5C9.9 5 8 6.8 8 9.7c0 5.3 7 4.4 7 6.8 0 1.3-1.1 1.7-2.7 1.7-2.3 0-4.5-.7-4.5-.7v3.1s2 .9 4.5.9c3.8 0 5.7-1.9 5.7-4.8 0-5.7-7-4.7-7-7.2z" fill="#fff"/>
    </svg>
  ),

  wave: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#00AF92"/>
      <path d="M3 12c1.5-3 3-4.5 4.5-4.5S10.5 9 12 9s3-1.5 4.5-1.5S19.5 9 21 12c-1.5 3-3 4.5-4.5 4.5S13.5 15 12 15s-3 1.5-4.5 1.5S4.5 15 3 12z" fill="#fff"/>
    </svg>
  ),

  dripjobs: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#0A1929"/>
      <path d="M12 4c0 0-5 5-5 9a5 5 0 0010 0c0-4-5-9-5-9z" fill="#FF6B35"/>
      <path d="M12 11c0 0-2.5 2.5-2.5 4.5a2.5 2.5 0 005 0C14.5 13.5 12 11 12 11z" fill="#fff" opacity=".5"/>
    </svg>
  ),

  roofr: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#1B62A4"/>
      <path d="M12 4L4 11h2v7h6v-5h4v5h6v-7h2L12 4z" fill="#fff"/>
    </svg>
  ),

  fieldpulse: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#2E7D32"/>
      <path d="M13 3L7 13h5l-1 8 7-10h-5l2-8z" fill="#fff"/>
    </svg>
  ),

  leap: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#FF6B35"/>
      <path d="M7 6h3v10h7v2.5H7V6z" fill="#fff"/>
    </svg>
  ),

  mhelpdesk: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#1565C0"/>
      <path d="M4 18V7h3l2.5 5.5L12 7h3v11h-2.5v-6.5L10 17H9l-2.5-5.5V18H4z" fill="#fff"/>
    </svg>
  ),

  kickserv: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#1976D2"/>
      <path d="M7 6h3v5l5-5h3.5L13 12l5.5 6H15l-5-5v5H7V6z" fill="#fff"/>
    </svg>
  ),

  nicejob: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#00BDA5"/>
      <path d="M12 3l2.5 5 5.5.8-4 3.9.9 5.5L12 15.5l-4.9 2.7.9-5.5-4-3.9 5.5-.8z" fill="#fff"/>
    </svg>
  ),

  csv_upload: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#334155"/>
      <path d="M13 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V9l-6-6zm1 1.5l4.5 4.5H14V4.5zM8 13h8v1.5H8V13zm0 3h5v1.5H8V16zm0-6h3v1.5H8V10z" fill="#fff"/>
    </svg>
  ),

  manual: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill="#475569"/>
      <path d="M4 20.5l5.5-5.5 1.5 1.5-5.5 5.5H4v-1.5zM19.5 5a1.5 1.5 0 010 2l-9 9-2-2 9-9a1.5 1.5 0 012-1.5l1 1z" fill="#fff"/>
    </svg>
  ),

};

export default function ServiceIcon({ type, size = 20 }) {
  const icon = icons[type];
  if (icon) return icon;
  // Fallback: first letter in a colored circle
  const colors = ['#6366F1','#EC4899','#F59E0B','#10B981','#3B82F6','#EF4444','#8B5CF6','#06B6D4'];
  const color = colors[(type || '').charCodeAt(0) % colors.length];
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="5" fill={color}/>
      <text x="12" y="16.5" textAnchor="middle" fontSize="13" fontWeight="700" fill="#fff" fontFamily="Arial,sans-serif">
        {(type || '?').charAt(0).toUpperCase()}
      </text>
    </svg>
  );
}

export { icons as SERVICE_ICONS };
