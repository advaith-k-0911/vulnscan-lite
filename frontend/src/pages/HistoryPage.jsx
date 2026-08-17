import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { listScans } from '../services/api';
import ScanStatus from '../components/ScanStatus';

export default function HistoryPage() {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Pagination state (1-indexed for UX)
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const fetchHistory = useCallback(async (targetPage = page) => {
    setLoading(true);
    setError(null);
    const offset = (targetPage - 1) * pageSize;

    try {
      const data = await listScans(pageSize, offset);
      setScans(data.items || []);
      setTotal(data.total || 0);
      setPage(targetPage);
    } catch (err) {
      setError(err.message || 'Unable to load previous scan history.');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize]);

  useEffect(() => {
    fetchHistory(1);
  }, []);

  const totalPages = Math.ceil(total / pageSize) || 1;

  const handlePrevPage = () => {
    if (page > 1) {
      fetchHistory(page - 1);
    }
  };

  const handleNextPage = () => {
    if (page < totalPages) {
      fetchHistory(page + 1);
    }
  };

  const getHostname = (url) => {
    try {
      const parsed = new URL(url.includes('://') ? url : `https://${url}`);
      return parsed.hostname;
    } catch {
      return url;
    }
  };

  const calculateDuration = (startedAt, completedAt) => {
    if (!startedAt || !completedAt) return null;
    const start = new Date(startedAt).getTime();
    const end = new Date(completedAt).getTime();
    if (isNaN(start) || isNaN(end) || end < start) return null;
    const seconds = ((end - start) / 1000).toFixed(1);
    return `${seconds}s`;
  };

  return (
    <main className="history-page-container">
      {/* Header Bar */}
      <section className="history-header-bar">
        <div className="history-header-left">
          <h1 className="history-title">Scan History</h1>
          <p className="history-subtitle">
            Review previous security assessments and open detailed reports from the database.
          </p>
        </div>
        <div className="history-header-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => fetchHistory(page)}
            disabled={loading}
            aria-label="Refresh scan history"
          >
            {loading ? <span className="spinner" aria-hidden="true"></span> : '🔄'} Refresh
          </button>
          <Link to="/" className="btn btn-primary">
            + New Scan
          </Link>
        </div>
      </section>

      {/* Loading State */}
      {loading && scans.length === 0 && (
        <section className="loading-card" role="status" aria-live="polite">
          <div className="spinner large" aria-hidden="true"></div>
          <p className="loading-text">Loading persistent scan records...</p>
        </section>
      )}

      {/* Error State */}
      {error && !loading && (
        <section className="error-banner" role="alert">
          <div className="error-banner-header">
            <span className="error-icon">✕</span>
            <strong>Unable to Load Scan History</strong>
          </div>
          <p className="error-banner-body">{error}</p>
          <div className="action-buttons-group">
            <button type="button" className="btn btn-primary" onClick={() => fetchHistory(1)}>
              Retry
            </button>
          </div>
        </section>
      )}

      {/* Empty State */}
      {!loading && !error && total === 0 && (
        <section className="empty-history-card">
          <span className="empty-icon">🛡️</span>
          <h2 className="empty-title">No Scans Recorded</h2>
          <p className="empty-description">
            You haven't conducted any passive security scans yet. Enter a target URL to start your first assessment.
          </p>
          <Link to="/" className="btn btn-primary">
            Start Your First Scan
          </Link>
        </section>
      )}

      {/* Populated Scan Records List */}
      {!error && total > 0 && (
        <section className="history-content-card" aria-label="Scan Records Table">
          <div className="table-responsive">
            <table className="history-table">
              <thead>
                <tr>
                  <th scope="col">Target Domain</th>
                  <th scope="col">Status</th>
                  <th scope="col">Score</th>
                  <th scope="col">Grade</th>
                  <th scope="col">Assessed Date</th>
                  <th scope="col">Duration</th>
                  <th scope="col" className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const isCompleted = scan.status === 'COMPLETED';
                  const isFailed = scan.status === 'FAILED';
                  const hostname = getHostname(scan.target_url);
                  const duration = calculateDuration(scan.started_at, scan.completed_at);
                  const dateStr = scan.completed_at || scan.created_at
                    ? new Date(scan.completed_at || scan.created_at).toLocaleString()
                    : 'N/A';

                  return (
                    <tr key={scan.id} className="history-row">
                      <td className="target-cell">
                        <span className="target-cell-host mono">{hostname}</span>
                        <span className="target-cell-url mono" title={scan.target_url}>
                          {scan.target_url}
                        </span>
                      </td>
                      <td>
                        <ScanStatus status={scan.status} />
                      </td>
                      <td className="score-cell mono">
                        {isCompleted && scan.score !== null ? (
                          <span className="score-number-text">{scan.score} / 100</span>
                        ) : (
                          <span className="text-muted">--</span>
                        )}
                      </td>
                      <td>
                        {isCompleted && scan.grade ? (
                          <span className={`grade-pill grade-${scan.grade.toLowerCase()}`}>
                            {scan.grade}
                          </span>
                        ) : (
                          <span className="text-muted">--</span>
                        )}
                      </td>
                      <td className="date-cell">{dateStr}</td>
                      <td className="duration-cell mono">{duration || '--'}</td>
                      <td className="action-cell text-right">
                        {isCompleted && (
                          <Link to={`/results/${scan.id}`} className="table-action-link">
                            View Report →
                          </Link>
                        )}
                        {isFailed && (
                          <Link to={`/results/${scan.id}`} className="table-action-link text-danger">
                            View Error →
                          </Link>
                        )}
                        {!isCompleted && !isFailed && (
                          <span className="table-action-link text-muted">In Progress</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="pagination-bar">
            <div className="pagination-info">
              Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, total)} of {total} scans
            </div>

            <div className="pagination-controls">
              <button
                type="button"
                className="btn btn-secondary pagination-btn"
                onClick={handlePrevPage}
                disabled={page <= 1 || loading}
                aria-label="Go to previous page"
              >
                ← Previous
              </button>
              <span className="page-indicator mono">
                Page {page} of {totalPages}
              </span>
              <button
                type="button"
                className="btn btn-secondary pagination-btn"
                onClick={handleNextPage}
                disabled={page >= totalPages || loading}
                aria-label="Go to next page"
              >
                Next →
              </button>
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
