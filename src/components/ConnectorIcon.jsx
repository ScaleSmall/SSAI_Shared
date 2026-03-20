import React from 'react';

const icons = {
  // CompanyCam — orange camera icon matching their brand
  companycam: (
    <svg width="22" height="22" viewBox="0 0 48 48" fill="none">
      <rect width="48" height="48" rx="10" fill="#F26522"/>
      <path d="M16 15l3-4h10l3 4h4a2 2 0 012 2v16a2 2 0 01-2 2H12a2 2 0 01-2-2V17a2 2 0 012-2h4z" fill="#fff"/>
      <circle cx="24" cy="24" r="6" fill="#F26522"/>
      <circle cx="24" cy="24" r="3.5" fill="#fff"/>
    </svg>
  ),
  // Google Drive — official tri-color triangle
  google_drive: (
    <svg width="22" height="22" viewBox="0 0 87.3 78" fill="none">
      <path d="M6.6 66.85L3.3 61.35 29.25 17.1h24.6L6.6 66.85z" fill="#0066DA"/>
      <path d="M57.6 78H10.8l13.3-22.9h46.8L57.6 78z" fill="#00AC47"/>
      <path d="M33.45 17.1L57.6 58.45 70.9 35.55 46.8 17.1h-13.35z" fill="#00AC47"/>
      <path d="M29.25 17.1l24.3 41.65 13.35-23.2L53.85 17.1H29.25z" fill="#EA4335"/>
      <path d="M70.9 55.1H24.1l13.3 22.9h46.8L70.9 55.1z" fill="#00832D"/>
      <path d="M53.85 17.1h-24.6L0 66.85l3.3 5.5L57.6 0l29.7 55.1H70.9L53.85 17.1z" fill="#2684FC"/>
      <path d="M84.15 78L70.9 55.1l-13.3 23H84.15z" fill="#FFBA00"/>
      <path d="M57.6 78h26.55L57.6 0 33.45 17.1 57.6 58.45V78z" fill="#5BB974"/>
      <path d="M24.1 55.1l-13.3 23h46.8V58.45L24.1 55.1z" fill="#00AC47"/>
    </svg>
  ),
  // Dropbox — official open box logo
  dropbox: (
    <svg width="22" height="22" viewBox="0 0 43 40" fill="#0061FF">
      <path d="M12.5 0L0 8.1l8.6 6.9 12.5-7.8L12.5 0zM0 21.9l12.5 8.1 8.6-7.2-12.5-7.8L0 21.9zM21.1 22.8l8.6 7.2L42.2 21.9l-8.6-6.9-12.5 7.8zM42.2 8.1L29.7 0l-8.6 7.2 12.5 7.8 8.6-6.9zM21.2 24.6l-8.6 7.1-3.9-2.5v2.8L21.2 40l12.5-8v-2.8l-3.9 2.5-8.6-7.1z"/>
    </svg>
  ),
  // Jobber — green J in rounded square matching their brand
  jobber: (
    <svg width="22" height="22" viewBox="0 0 48 48" fill="none">
      <rect width="48" height="48" rx="10" fill="#7AC143"/>
      <path d="M28 12h-4v18c0 2.2-1.8 4-4 4s-4-1.8-4-4h-4c0 4.4 3.6 8 8 8s8-3.6 8-8V12z" fill="#fff"/>
      <circle cx="26" cy="12" r="3" fill="#fff"/>
    </svg>
  ),
  // Manual Upload — clean upload arrow
  manual_upload: (
    <svg width="22" height="22" viewBox="0 0 48 48" fill="none">
      <rect width="48" height="48" rx="10" fill="#6366f1"/>
      <path d="M24 14l-8 8h5v10h6V22h5l-8-8zM14 34h20v3H14v-3z" fill="#fff"/>
    </svg>
  ),
};

export default function ConnectorIcon({ type }) {
  return icons[type] || <span style={{ fontSize: 16, fontWeight: 700 }}>{type?.charAt(0)?.toUpperCase()}</span>;
}
