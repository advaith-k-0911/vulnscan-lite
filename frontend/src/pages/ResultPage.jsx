import React, { useEffect, useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getScan, downloadScanPdf } from '../services/api';
import ScoreGauge from '../components/ScoreGauge';
import FindingCard from '../components/FindingCard';
import ScanStatus from '../components/ScanStatus';

export default function ResultPage() {
  const { scanId } = useParams();
  const [scanRecord, setScanRecord] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState(null);

  // Filter state
  const [statusFilter, setStatusFilter] = useState('ALL'); // 'ALL', 'FAIL', 'WARNING', 'PASS'
  const [categoryFilter, setCategoryFilter] = useState('ALL'); // 'ALL', 'security_headers', 'tls', 'network', 'cms'

  const fetchScanReport = () => {
    setLoading(true);
    setError(null);
    getScan(scanId)
      .then((data) => {
        setScanRecord(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to load security scan report.');
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchScanReport();
  }, [scanId]);

  const handleDownloadPdf = async () => {
    if (isDownloading) return;
    setIsDownloading(true);
    setDownloadError(null);

    try {
      await downloadScanPdf(scanId);
    } catch (err) {
      setDownloadError(err.message || 'Failed to generate and download the PDF report.');
    } finally {
      setIsDownloading(false);
    }
  };

  const findings = useMemo(() => {
    return scanRecord?.result?.findings || [];
  }, [scanRecord]);

  const summary = useMemo(() => {
    if (scanRecord?.result?.summary) {
      return scanRecord.result.summary;
    }
    const total = findings.length;
    const passed = findings.filter((f) => f.status === 'PASS').length;
    const failed = findings.filter((f) => f.status === 'FAIL').length;
    const warnings = findings.filter((f) => f.status === 'WARNING').length;
    return { total, passed, failed, warnings };
  }, [scanRecord, findings]);

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      if (statusFilter !== 'ALL') {
        if (statusFilter === 'FAIL' && finding.status !== 'FAIL') return false;
        if (statusFilter === 'WARNING' && finding.status !== 'WARNING') return false;
        if (statusFilter === 'PASS' && finding.status !== 'PASS') return false;
      }
      if (categoryFilter !== 'ALL' && finding.category !== categoryFilter) {
        return false;
      }
      return true;
    });
  }, [findings, statusFilter, categoryFilter]);

  if (loading) {
    return (
      <main className="result-page-container">
        <div className="loading-card" role="status" aria-live="polite">
          <div className="spinner large" aria-hidden="true"></div>
          <p className="loading-text">Retrieving persisted security scan report...</p>
        </div>
      </main>
    );
  }

  if (error || !scanRecord) {
    return (
      <main className="result-page-container">
        <div className="error-banner" role="alert">
          <div className="error-banner-header">
            <span className="error-icon">✕</span>
            <strong>Unable to Load Report</strong>
          </div>
          <p className="error-banner-body">
            {error || `No scan record found with ID: ${scanId}`}
          </p>
          <div className="action-buttons-group">
            <button type="button" className="btn btn-primary" onClick={fetchScanReport}>
              Try Again
            </button>
            <Link to="/" className="btn btn-secondary">
              Back to Scanner
            </Link>
          </div>
        </div>
      </main>
    );
  }

  const { target_url, status, score, grade, result, completed_at } = scanRecord;
  const isCompleted = status === 'COMPLETED';

  let hostname = target_url;
  try {
    const parsed = new URL(target_url.includes('://') ? target_url : `https://${target_url}`);
    hostname = parsed.hostname;
  } catch {
    hostname = target_url;
  }

  const formattedDate = completed_at ? new Date(completed_at).toLocaleString() : 'N/A';

  return (
    <main className="result-page-container">
      {/* Top Header Navigation & Actions */}
      <div className="result-header-bar">
        <div className="result-header-left">
          <Link to="/" className="back-link">
            ← Back to Scanner
          </Link>
          <div className="result-target-row">
            <h1 className="result-target-title mono">{hostname}</h1>
            <ScanStatus status={status} />
          </div>
          <span className="result-full-url mono">{target_url}</span>
        </div>

        <div className="result-header-right">
          {isCompleted && (
            <button
              type="button"
              className="btn btn-secondary download-pdf-btn"
              onClick={handleDownloadPdf}
              disabled={isDownloading}
              aria-label="Download executive PDF security report"
            >
              {isDownloading ? (
                <>
                  <span className="spinner" aria-hidden="true"></span>
                  <span>Generating PDF...</span>
                </>
              ) : (
                <>
                  <span aria-hidden="true">📄</span>
                  <span>Download PDF</span>
                </>
              )}
            </button>
          )}
          <Link to="/" className="action-btn">
            Start New Scan
          </Link>
        </div>
      </div>

      {downloadError && (
        <div className="error-banner" role="alert">
          <div className="error-banner-header">
            <span className="error-icon">✕</span>
            <strong>PDF Generation Failed</strong>
          </div>
          <p className="error-banner-body">{downloadError}</p>
        </div>
      )}

      {/* Main Score & Posture Overview Card */}
      <section className="score-overview-card" aria-label="Security Posture Score">
        <ScoreGauge score={score} grade={grade} />

        <div className="posture-metrics-container">
          <div className="metrics-header">
            <h2 className="metrics-title">Security Posture Overview</h2>
            <span className="metrics-timestamp">Assessed: {formattedDate}</span>
          </div>

          <div className="metadata-grid">
            <div className="meta-card">
              <span className="meta-label">Total Checks</span>
              <span className="meta-value">{summary.total || summary.total_checks || findings.length}</span>
            </div>
            <div className="meta-card">
              <span className="meta-label">Passed Checks</span>
              <span className="meta-value text-success">{summary.passed || 0}</span>
            </div>
            <div className="meta-card">
              <span className="meta-label">Failed Checks</span>
              <span className="meta-value text-danger">{summary.failed || 0}</span>
            </div>
            <div className="meta-card">
              <span className="meta-label">Warnings</span>
              <span className="meta-value text-warning">{summary.warnings || 0}</span>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Diagnostics Strip */}
      <section className="summary-section" aria-label="Target Configuration Diagnostics">
        <h2 className="section-title">Configuration Diagnostics</h2>
        <div className="summary-cards-grid">
          <div className="summary-box">
            <span className="summary-box-title">HTTP & Latency</span>
            <p className="summary-box-desc">
              Status Code: <strong>{result?.http?.status_code || 'N/A'}</strong> | Latency:{' '}
              <strong>{result?.http?.response_time ? `${result.http.response_time}s` : 'N/A'}</strong>
            </p>
          </div>

          <div className="summary-box">
            <span className="summary-box-title">TLS Protocol & Cipher</span>
            <p className="summary-box-desc">
              Status:{' '}
              <strong className={result?.tls?.status === 'PASS' ? 'text-success' : 'text-warning'}>
                {result?.tls?.status || 'N/A'}
              </strong>{' '}
              | Cipher:{' '}
              <strong>{result?.tls?.connection?.cipher_suite || 'N/A'}</strong>
            </p>
          </div>

          <div className="summary-box">
            <span className="summary-box-title">CMS Fingerprint</span>
            <p className="summary-box-desc">
              {result?.cms?.detected ? (
                <>
                  Detected: <strong>{result.cms.cms}</strong> (Confidence: {result.cms.confidence})
                </>
              ) : (
                'No standard CMS signatures detected'
              )}
            </p>
          </div>
        </div>
      </section>

      {/* Findings Section with Filter Controls */}
      <section className="findings-section" aria-label="Security Findings Breakdown">
        <div className="findings-header-row">
          <h2 className="section-title">Assessment Findings ({findings.length})</h2>

          {/* Status Filter Tabs */}
          <div className="status-filter-tabs" role="tablist" aria-label="Filter findings by status">
            <button
              type="button"
              role="tab"
              aria-selected={statusFilter === 'ALL'}
              className={`filter-tab-btn ${statusFilter === 'ALL' ? 'active' : ''}`}
              onClick={() => setStatusFilter('ALL')}
            >
              All ({findings.length})
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={statusFilter === 'FAIL'}
              className={`filter-tab-btn ${statusFilter === 'FAIL' ? 'active' : ''}`}
              onClick={() => setStatusFilter('FAIL')}
            >
              Failed ({summary.failed || 0})
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={statusFilter === 'WARNING'}
              className={`filter-tab-btn ${statusFilter === 'WARNING' ? 'active' : ''}`}
              onClick={() => setStatusFilter('WARNING')}
            >
              Warnings ({summary.warnings || 0})
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={statusFilter === 'PASS'}
              className={`filter-tab-btn ${statusFilter === 'PASS' ? 'active' : ''}`}
              onClick={() => setStatusFilter('PASS')}
            >
              Passed ({summary.passed || 0})
            </button>
          </div>
        </div>

        {/* Category Filter Pills */}
        <div className="category-filter-pills" role="toolbar" aria-label="Filter findings by category">
          <button
            type="button"
            className={`cat-pill-btn ${categoryFilter === 'ALL' ? 'active' : ''}`}
            onClick={() => setCategoryFilter('ALL')}
          >
            All Categories
          </button>
          <button
            type="button"
            className={`cat-pill-btn ${categoryFilter === 'security_headers' ? 'active' : ''}`}
            onClick={() => setCategoryFilter('security_headers')}
          >
            Security Headers
          </button>
          <button
            type="button"
            className={`cat-pill-btn ${categoryFilter === 'tls' ? 'active' : ''}`}
            onClick={() => setCategoryFilter('tls')}
          >
            TLS / SSL
          </button>
          <button
            type="button"
            className={`cat-pill-btn ${categoryFilter === 'network' ? 'active' : ''}`}
            onClick={() => setCategoryFilter('network')}
          >
            HTTP & Network
          </button>
          <button
            type="button"
            className={`cat-pill-btn ${categoryFilter === 'cms' ? 'active' : ''}`}
            onClick={() => setCategoryFilter('cms')}
          >
            CMS Fingerprint
          </button>
        </div>

        {/* Findings List */}
        <div className="findings-list">
          {filteredFindings.length > 0 ? (
            filteredFindings.map((finding) => (
              <FindingCard key={finding.id || finding.name} finding={finding} />
            ))
          ) : (
            <div className="empty-findings-box">
              <span className="empty-icon">✓</span>
              {statusFilter === 'FAIL' && <p>All evaluated checks in this category passed!</p>}
              {statusFilter === 'WARNING' && <p>No warnings detected in this category.</p>}
              {statusFilter === 'PASS' && <p>No passed checks match the current filter.</p>}
              {statusFilter === 'ALL' && <p>No findings available for the selected category.</p>}
            </div>
          )}
        </div>
      </section>
    </main>
  );
}
