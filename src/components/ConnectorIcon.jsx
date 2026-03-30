import React from 'react';
import ServiceIcon from './ServiceIcon.jsx';

/**
 * Connector icon — delegates to ServiceIcon so all brand icons live in one place.
 */
export default function ConnectorIcon({ type, size = 20 }) {
  return <ServiceIcon type={type} size={size} />;
}
