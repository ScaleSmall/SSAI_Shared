import React from 'react';

/**
 * Brand icons for connectors (photo sources) and data sources (CRMs).
 * Usage: <ServiceIcon type="companycam" /> or <ServiceIcon type="quickbooks" />
 */

const icons = {
  // ===== Connectors (photo sources) =====
  companycam: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14.5v-9l7 4.5-7 4.5z" opacity=".15"/>
      <path d="M9 3.5L4.5 8H2v9h4.5L12 21.5V3.5H9zM6 15H4v-5h2v5zm2-6.12v7.24L5.88 14H4v-3h1.88L8 8.88z" opacity="0"/>
      <path d="M20 4h-3.17L15.41 2.59A2 2 0 0014 2H10a2 2 0 00-1.41.59L7.17 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V6a2 2 0 00-2-2zm0 14H4V6h4.05l1.83-2h4.24l1.83 2H20v12zM12 7a5 5 0 100 10 5 5 0 000-10zm0 8a3 3 0 110-6 3 3 0 010 6z"/>
    </svg>
  ),
  google_drive: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <path d="M8.627 1.5L1.5 13.863l3.373 5.637h7.254L8.627 1.5z" fill="#0066DA"/>
      <path d="M15.373 1.5H8.627l7.5 12.363h7.373L15.373 1.5z" fill="#00AC47"/>
      <path d="M1.5 13.863l3.373 5.637H23.5l-3.373-5.637H1.5z" fill="#EA4335"/>
      <path d="M12.127 7.932L8.627 1.5l-3.754 6.432 3.5 5.931h7.254l-3.5-5.931z" fill="#00832D"/>
      <path d="M16.127 13.863h-7.5l3.5 5.637h7.373l-3.373-5.637z" fill="#2684FC"/>
      <path d="M8.627 1.5l3.5 6.432L15.373 1.5H8.627z" fill="#FFBA00"/>
    </svg>
  ),
  dropbox: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="#0061FF">
      <path d="M6 2l6 3.75L6 9.5 0 5.75zM18 2l6 3.75-6 3.75-6-3.75zM0 13.25L6 9.5l6 3.75L6 17zM18 9.5l6 3.75L18 17l-6-3.75zM6 18.25l6-3.75 6 3.75-6 3.75z"/>
    </svg>
  ),
  jobber: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="4" fill="#7AC143"/>
      <path d="M7 6h4v12H7V6zm6 3h4v9h-4V9z" fill="#fff"/>
    </svg>
  ),
  manual_upload: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M9 16h6v-6h4l-7-7-7 7h4v6zm-4 2h14v2H5v-2z"/>
    </svg>
  ),

  // ===== Data Sources (CRMs / business tools) =====
  ghl: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="4" fill="#0B7B3E"/>
      <path d="M12 4L6 8v4l6 4 6-4V8l-6-4zm0 2.4l3.6 2.4v2.4L12 13.6 8.4 11.2V8.8L12 6.4zM6 14v2l6 4 6-4v-2l-6 4-6-4z" fill="#fff"/>
    </svg>
  ),
  paintscout: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="4" fill="#2563EB"/>
      <path d="M7 4h2v7l3-3 3 3V4h2v9l-5 5-5-5V4zm5 12.5L9.5 14h5L12 16.5z" fill="#fff"/>
    </svg>
  ),
  quickbooks: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="11" fill="#2CA01C"/>
      <path d="M7.5 8.5a3 3 0 000 6h2v-1.5h-2a1.5 1.5 0 010-3h1V8.5h-1zm4-1v9h1.5v-3h2a3 3 0 000-6h-3.5zm1.5 1.5h2a1.5 1.5 0 010 3h-2V9z" fill="#fff"/>
    </svg>
  ),
  servicetitan: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="4" fill="#DF2A24"/>
      <path d="M7 6l5 3v6l-5 3V6zm5 3l5-3v12l-5-3V9z" fill="#fff"/>
    </svg>
  ),
  housecall_pro: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="4" fill="#0369A1"/>
      <path d="M12 3l-8 7h3v8h4v-5h2v5h4v-8h3l-8-7z" fill="#fff"/>
    </svg>
  ),
  square: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="4" fill="#000"/>
      <rect x="5" y="5" width="14" height="14" rx="2" fill="#fff"/>
      <rect x="8" y="8" width="8" height="8" rx="1" fill="#000"/>
    </svg>
  ),
  csv_upload: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6zm-1 2l5 5h-5V4zM8 17v-1h2v1H8zm0-3v-1h4v1H8zm0-3v-1h6v1H8z"/>
    </svg>
  ),
  manual: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1 1 0 000-1.41l-2.34-2.34a1 1 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/>
    </svg>
  ),
};

export default function ServiceIcon({ type, size = 20 }) {
  const icon = icons[type];
  if (icon) return icon;
  // Fallback: first letter in a circle
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
      <circle cx="12" cy="12" r="11" fill="currentColor" opacity="0.15"/>
      <text x="12" y="16" textAnchor="middle" fontSize="12" fontWeight="600" fill="currentColor">
        {(type || '?').charAt(0).toUpperCase()}
      </text>
    </svg>
  );
}

export { icons as SERVICE_ICONS };
