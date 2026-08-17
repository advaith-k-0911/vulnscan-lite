import React from 'react';

/**
 * Reusable Status Indicator Component.
 * Communicates real backend lifecycle states using icons, text, and accessible attributes.
 *
 * @param {Object} props
 * @param {'IDLE'|'QUEUED'|'RUNNING'|'COMPLETED'|'FAILED'} props.status
 * @param {string} [props.className]
 */
export default function ScanStatus({ status = 'IDLE', className = '' }) {
  const normalizedStatus = status.toUpperCase();

  const getStatusConfig = () => {
    switch (normalizedStatus) {
      case 'QUEUED':
        return {
          label: 'Queued',
          icon: '⏳',
          ariaText: 'Status: Queued in background worker queue',
          classSuffix: 'queued',
        };
      case 'RUNNING':
        return {
          label: 'Scanning',
          icon: '⚡',
          ariaText: 'Status: Active passive scan in progress',
          classSuffix: 'running',
        };
      case 'COMPLETED':
        return {
          label: 'Completed',
          icon: '✓',
          ariaText: 'Status: Scan completed successfully',
          classSuffix: 'completed',
        };
      case 'FAILED':
        return {
          label: 'Failed',
          icon: '✕',
          ariaText: 'Status: Scan execution failed',
          classSuffix: 'failed',
        };
      case 'IDLE':
      default:
        return {
          label: 'Idle',
          icon: '•',
          ariaText: 'Status: Ready to scan',
          classSuffix: 'idle',
        };
    }
  };

  const config = getStatusConfig();

  return (
    <span
      className={`scan-status-badge status-${config.classSuffix} ${className}`}
      role="status"
      aria-label={config.ariaText}
    >
      <span className="status-badge-icon" aria-hidden="true">
        {config.icon}
      </span>
      <span className="status-badge-text">{config.label}</span>
    </span>
  );
}
