import React, { useEffect } from 'react';

export default function Toast({ message, onDone, duration = 4000 }) {
  useEffect(() => {
    if (!onDone) return;
    const t = setTimeout(onDone, duration);
    return () => clearTimeout(t);
  }, [onDone, duration]);

  return (
    <div className="sc-toast" onClick={onDone} style={{ cursor: onDone ? 'pointer' : 'default' }}>
      {message}
    </div>
  );
}
