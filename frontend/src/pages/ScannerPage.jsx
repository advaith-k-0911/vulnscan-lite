import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createScan } from '../services/api';
import { useScanPolling } from '../hooks/useScanPolling';
import ScanProgress from '../components/ScanProgress';

export default function ScannerPage() {
  const navigate = useNavigate();
  const [urlInput, setUrlInput] = useState('');
  const [inputError, setInputError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const [activeTarget, setActiveTarget] = useState('');

  // Polling hook for asynchronous scan lifecycle
  const {
    status,
    isPolling,
    error: pollingError,
    networkWarning,
    resetPolling,
  } = useScanPolling(activeScanId, {
    onComplete: (data) => {
      // Transition smoothly to the results page once completed
      navigate(`/results/${data.id}`);
    },
  });

  const validateUrl = (rawUrl) => {
    const trimmed = rawUrl.trim();
    if (!trimmed) {
      return 'Target URL cannot be empty.';
    }

    try {
      const parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return 'Only HTTP and HTTPS protocols are supported.';
      }
      if (!parsed.hostname || !parsed.hostname.includes('.')) {
        return 'Please provide a valid domain name (e.g., example.com).';
      }
    } catch {
      return 'Please enter a valid website URL.';
    }

    return '';
  };

  const startScanForUrl = async (targetUrl) => {
    setIsSubmitting(true);
    setInputError('');
    try {
      const response = await createScan(targetUrl);
      setActiveScanId(response.scan_id);
      setActiveTarget(targetUrl);
    } catch (err) {
      setInputError(err.message || 'Failed to submit scan request. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const validationMsg = validateUrl(urlInput);
    if (validationMsg) {
      setInputError(validationMsg);
      return;
    }

    const targetUrl = urlInput.trim().includes('://')
      ? urlInput.trim()
      : `https://${urlInput.trim()}`;

    await startScanForUrl(targetUrl);
  };

  const handleRetry = async () => {
    if (activeTarget) {
      resetPolling();
      await startScanForUrl(activeTarget);
    }
  };

  const handleReset = () => {
    resetPolling();
    setActiveScanId(null);
    setActiveTarget('');
    setUrlInput('');
    setInputError('');
  };

  return (
    <main className="scanner-page-container">
      <section className="hero-section">
        <div className="hero-badge">PASSIVE RECONNAISSANCE & CONFIGURATION AUDIT</div>
        <h1 className="hero-title">VulnScan Lite</h1>
        <p className="hero-subtitle">
          Passive Web Security & Configuration Posture Scanner
        </p>
      </section>

      {/* Prominent Safety Disclaimer */}
      <section className="disclaimer-banner" aria-label="Legal & Safety Notice">
        <div className="disclaimer-icon">⚠️</div>
        <div className="disclaimer-text">
          <strong>Mandatory Authorization Notice:</strong> Only scan websites you own or have explicit
          permission to assess. This tool performs non-intrusive, passive security configuration analysis only.
        </div>
      </section>

      {/* Main Scan Input Card */}
      {!activeScanId ? (
        <section className="scan-card">
          <form onSubmit={handleSubmit} className="scan-form" noValidate>
            <div className="input-group">
              <label htmlFor="target-url-input" className="input-label">
                Target Website URL
              </label>
              <div className="input-wrapper">
                <div className="url-input-inner">
                  <span className="url-prefix-icon" aria-hidden="true">🌐</span>
                  <input
                    id="target-url-input"
                    type="text"
                    className={`url-input ${inputError ? 'input-invalid' : ''}`}
                    placeholder="https://example.com"
                    value={urlInput}
                    onChange={(e) => {
                      setUrlInput(e.target.value);
                      if (inputError) setInputError('');
                    }}
                    disabled={isSubmitting}
                    aria-required="true"
                    aria-invalid={!!inputError}
                    aria-describedby={inputError ? 'url-error-msg' : undefined}
                    autoComplete="off"
                    spellCheck="false"
                  />
                </div>
                <button
                  type="submit"
                  className="scan-submit-btn"
                  disabled={isSubmitting || !urlInput.trim()}
                  aria-busy={isSubmitting}
                >
                  {isSubmitting ? (
                    <>
                      <span className="spinner" aria-hidden="true"></span>
                      <span>Submitting...</span>
                    </>
                  ) : (
                    <span>Start Scan</span>
                  )}
                </button>
              </div>
              {inputError && (
                <p id="url-error-msg" className="error-message" role="alert">
                  {inputError}
                </p>
              )}
            </div>
          </form>
        </section>
      ) : (
        /* Real-Time Scan Progress View */
        <ScanProgress
          targetUrl={activeTarget}
          scanId={activeScanId}
          status={status}
          error={pollingError}
          networkWarning={networkWarning}
          onReset={handleReset}
          onRetry={handleRetry}
        />
      )}
    </main>
  );
}
