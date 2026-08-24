import React from 'react';
import { Link } from 'react-router-dom';
import ScanStatus from './ScanStatus';

/**
 * Scan Progress Component.
 * Accurately communicates real backend lifecycle states without fake percentages.
 *
 * @param {Object} props
 * @param {string} props.targetUrl - Target URL being scanned
 * @param {string} props.scanId - Scan Job UUID
 * @param {'QUEUED'|'RUNNING'|'COMPLETED'|'FAILED'} props.status - Real backend status
 * @param {Object|null} [props.scanData] - Full completed scan record if available
 * @param {string|null} [props.error] - Safe error message if failed
 * @param {string|null} [props.networkWarning] - Transient network retry notice
 * @param {Function} [props.onReset] - Handler to start another scan
 * @param {Function} [props.onRetry] - Handler to retry scanning the same target
 */
export default function ScanProgress({
  targetUrl,
  scanId,
  status,
  scanData,
  error,
  networkWarning,
  onReset,
  onRetry,
}) {
  let hostname = '';
  try {
    const parsed = new URL(targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`);
    hostname = parsed.hostname;
  } catch {
    hostname = targetUrl;
  }

  const isFailed = status === 'FAILED';
  const isQueued = status === 'QUEUED';
  const isRunning = status === 'RUNNING';
  const isCompleted = status === 'COMPLETED';

  return (
    <section className="scan-progress-container" aria-live="polite" aria-atomic="true">
      <div className="progress-top-bar">
        <div className="target-badge-area">
          <span className="target-sublabel">SCAN TARGET</span>
          <span className="target-hostname mono">{hostname}</span>
          <span className="target-full-url mono">{targetUrl}</span>
        </div>
        <ScanStatus status={status} />
      </div>

      {/* Main Status Information Card */}
      <div className={`progress-state-panel panel-${status.toLowerCase()}`}>
        {isQueued && (
          <div className="state-content">
            <div className="state-icon-wrapper">
              <span className="state-pulse-icon">⏳</span>
            </div>
            <div className="state-text-block">
              <h3 className="state-heading">Your scan has been queued</h3>
              <p className="state-description">
                The request has been accepted by the task queue. The scanner worker will begin shortly.
              </p>
            </div>
          </div>
        )}

        {isRunning && (
          <div className="state-content">
            <div className="state-icon-wrapper">
              <div className="radar-spinner" aria-hidden="true"></div>
            </div>
            <div className="state-text-block">
              <h3 className="state-heading">Security scan in progress</h3>
              <p className="state-description">
                Performing passive configuration analysis against public HTTP headers, TLS certificate parameters, and CMS signatures.
              </p>
            </div>
          </div>
        )}

        {isCompleted && (
          <div className="state-content">
            <div className="state-icon-wrapper success">
              <span className="state-success-icon">✓</span>
            </div>
            <div className="state-text-block">
              <h3 className="state-heading text-success">Scan Completed</h3>
              <p className="state-description">
                Security assessment completed successfully.
                {scanData?.score !== undefined && scanData?.score !== null && (
                  <> Overall Security Score: <strong className="mono">{scanData.score}/100</strong> (Grade {scanData.grade || 'N/A'}).</>
                )}
              </p>
            </div>
          </div>
        )}

        {isFailed && (
          <div className="state-content">
            <div className="state-icon-wrapper failed">
              <span className="state-failed-icon">✕</span>
            </div>
            <div className="state-text-block">
              <h3 className="state-heading text-danger">Scan could not be completed</h3>
              <p className="state-description text-danger-subtle">
                {error || 'An error occurred during passive target analysis. Please verify the target is reachable.'}
              </p>
            </div>
          </div>
        )}

        {/* Transient Network Reconnection Banner */}
        {networkWarning && (
          <div className="network-warning-box" role="alert">
            <span className="warning-icon">⚠️</span>
            <span>{networkWarning}</span>
          </div>
        )}
      </div>

      {/* Job Metadata & Actions */}
      <div className="progress-footer-bar">
        <div className="job-meta">
          <span className="meta-muted-label">Scan ID:</span>
          <code className="meta-id-code mono" title="Scan UUID">
            {scanId}
          </code>
        </div>

        <div className="progress-actions">
          {isCompleted ? (
            <div className="action-buttons-group">
              <Link to={`/results/${scanId}`} className="btn btn-primary">
                View Full Results →
              </Link>
              {onReset && (
                <button type="button" className="btn btn-secondary" onClick={onReset}>
                  Scan Another Website
                </button>
              )}
            </div>
          ) : isFailed ? (
            <div className="action-buttons-group">
              {onRetry && (
                <button type="button" className="btn btn-primary" onClick={onRetry}>
                  Try Again
                </button>
              )}
              {onReset && (
                <button type="button" className="btn btn-secondary" onClick={onReset}>
                  Scan Another Website
                </button>
              )}
            </div>
          ) : (
            <div className="polling-indicator-group">
              <span className="live-dot" aria-hidden="true"></span>
              <span className="live-text">Live status polling (2s)</span>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
