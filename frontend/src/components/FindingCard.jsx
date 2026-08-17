import React, { useState } from 'react';
import CodeSnippet from './CodeSnippet';

/**
 * FindingCard Component
 * Displays a single security check outcome, technical rationale, and remediation.
 *
 * @param {Object} props
 * @param {Object} props.finding
 */
export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);

  const {
    id,
    name,
    category,
    status = 'INFO',
    severity = 'INFO',
    points = 0,
    applicable = true,
    description = '',
    details = '',
    remediation = null,
  } = finding;

  const getStatusBadge = (st) => {
    switch (st.toUpperCase()) {
      case 'PASS':
        return <span className="status-pill status-completed">✓ Pass</span>;
      case 'FAIL':
        return <span className="status-pill status-failed">✕ Fail</span>;
      case 'WARNING':
        return <span className="status-pill status-queued">⚠️ Warning</span>;
      case 'INFO':
      default:
        return <span className="status-pill status-idle">ℹ Info</span>;
    }
  };

  const getSeverityBadge = (sev) => {
    const sevUpper = (sev || 'INFO').toUpperCase();
    let sevClass = 'sev-info';
    if (sevUpper === 'HIGH') sevClass = 'sev-high';
    else if (sevUpper === 'MEDIUM') sevClass = 'sev-medium';
    else if (sevUpper === 'LOW') sevClass = 'sev-low';

    return <span className={`severity-tag ${sevClass}`}>{sevUpper}</span>;
  };

  const formatCategoryName = (cat) => {
    switch (cat) {
      case 'security_headers':
        return 'Security Headers';
      case 'tls':
        return 'TLS / SSL';
      case 'network':
        return 'HTTP & Network';
      case 'cms':
        return 'CMS Fingerprint';
      default:
        return cat || 'General';
    }
  };

  const hasRemediation = remediation && (remediation.recommendation || remediation.configuration_examples);

  return (
    <article className={`finding-card card-${status.toLowerCase()}`}>
      <div className="finding-header">
        <div className="finding-title-row">
          <div className="finding-status-group">
            {getStatusBadge(status)}
            <span className="finding-category-tag">{formatCategoryName(category)}</span>
          </div>

          <div className="finding-meta-tags">
            {status !== 'PASS' && severity && getSeverityBadge(severity)}
            {points < 0 && (
              <span className="deduction-tag" title="Points deducted from overall score">
                {points} pts
              </span>
            )}
          </div>
        </div>

        <h3 className="finding-name">{name}</h3>
        {description && <p className="finding-description">{description}</p>}
      </div>

      {details && (
        <div className="finding-details-box">
          <span className="details-label">Observation:</span>
          <p className="details-text">{details}</p>
        </div>
      )}

      {/* Remediation Guide */}
      {hasRemediation && (
        <div className="remediation-section">
          <button
            type="button"
            className="remediation-toggle-btn"
            onClick={() => setExpanded(!expanded)}
            aria-expanded={expanded}
          >
            <span>🛠️ How to Remediate</span>
            <span className="toggle-icon">{expanded ? '▲' : '▼'}</span>
          </button>

          {expanded && (
            <div className="remediation-content-panel">
              {remediation.why_it_matters && (
                <div className="rem-block">
                  <h4 className="rem-subtitle">Technical Rationale & Risk</h4>
                  <p className="rem-text">{remediation.why_it_matters}</p>
                </div>
              )}

              {remediation.recommendation && (
                <div className="rem-block">
                  <h4 className="rem-subtitle">Recommended Action</h4>
                  <p className="rem-text">{remediation.recommendation}</p>
                </div>
              )}

              {remediation.configuration_examples && Object.keys(remediation.configuration_examples).length > 0 && (
                <div className="rem-block">
                  <h4 className="rem-subtitle">Server Configuration Examples</h4>
                  <CodeSnippet snippets={remediation.configuration_examples} />
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </article>
  );
}
