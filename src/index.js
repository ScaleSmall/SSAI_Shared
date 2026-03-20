// SSAI Shared — Components, hooks, and config for ScaleSmall apps
// Usage: import { ConnectPanel, useConnect, PLATFORM_META } from 'ssai-shared';

export { default as ConnectPanel, PlatformRow, ConnectorRow } from './components/ConnectPanel.jsx';
export { default as PlatformIcon } from './components/PlatformIcon.jsx';
export { default as ConnectorIcon } from './components/ConnectorIcon.jsx';
export { default as Toast } from './components/Toast.jsx';
export { default as EmailIdentity } from './components/EmailIdentity.jsx';
export { default as DataSourcePanel } from './components/DataSourcePanel.jsx';
export { useConnect } from './hooks/useConnect.js';
export { PLATFORM_ORDER, PLATFORM_META, CONNECTOR_ICONS, buildConnectUrls } from './config.js';
