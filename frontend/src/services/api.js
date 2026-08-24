/**
 * Centralized API Service for VulnScan Lite Backend Communication.
 * Includes defensive error parsing and 429 Rate Limit handling.
 */

const configuredApiBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim();
const API_BASE_URL = configuredApiBaseUrl
  ? configuredApiBaseUrl.replace(/\/+$/, '')
  : (import.meta.env.DEV ? 'http://127.0.0.1:8000' : '');

export class ApiError extends Error {
  constructor(message, status = null, code = null, retryAfter = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

/**
 * Helper to handle fetch responses and standardized errors.
 */
async function handleResponse(response) {
  let data = null;
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    let errorMsg = 'An unexpected server error occurred.';
    let errorCode = 'SERVER_ERROR';
    const retryAfter = response.headers.get('retry-after');

    if (response.status === 429) {
      errorMsg = 'Too many scan requests. Please wait and try again.';
      errorCode = 'RATE_LIMITED';
      if (retryAfter) {
        errorMsg += ` (Retry after ${retryAfter}s)`;
      }
    } else if (response.status === 413) {
      errorMsg = 'Request payload exceeds maximum allowed size.';
      errorCode = 'PAYLOAD_TOO_LARGE';
    }

    if (data) {
      if (typeof data.detail === 'string') {
        errorMsg = data.detail;
      } else if (Array.isArray(data.detail) && data.detail.length > 0) {
        errorMsg = data.detail.map((d) => d.msg || JSON.stringify(d)).join(', ');
      } else if (data.message) {
        errorMsg = data.message;
      }
      if (data.code) {
        errorCode = data.code;
      }
    }

    throw new ApiError(errorMsg, response.status, errorCode, retryAfter);
  }

  return data;
}

/**
 * Queue a new passive security scan.
 * @param {string} targetUrl
 * @returns {Promise<{scan_id: string, status: string, message: string}>}
 */
export async function createScan(targetUrl) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ target_url: targetUrl }),
    });
    return await handleResponse(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      'Unable to connect to the VulnScan API server. Please ensure the backend is running.',
      0,
      'NETWORK_ERROR'
    );
  }
}

/**
 * Retrieve current lifecycle status for a scan job.
 * @param {string} scanId
 * @returns {Promise<{scan_id: string, status: string}>}
 */
export async function getScanStatus(scanId) {
  try {
    const response = await fetch(
      `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}/status`,
      { cache: 'no-store' }
    );
    return await handleResponse(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('Failed to fetch scan status from server.', 0, 'NETWORK_ERROR');
  }
}

/**
 * Retrieve full scan record and report findings.
 * @param {string} scanId
 * @returns {Promise<Object>}
 */
export async function getScan(scanId) {
  try {
    const response = await fetch(
      `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}`,
      { cache: 'no-store' }
    );
    return await handleResponse(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('Failed to fetch scan results from server.', 0, 'NETWORK_ERROR');
  }
}

/**
 * Download executive PDF security assessment report.
 * @param {string} scanId
 * @returns {Promise<void>}
 */
export async function downloadScanPdf(scanId) {
  try {
    const response = await fetch(
      `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}/report/pdf`
    );

    if (!response.ok) {
      let errorMsg = 'Failed to generate PDF report.';
      try {
        const errorJson = await response.json();
        if (errorJson?.detail) errorMsg = errorJson.detail;
      } catch {
        // ignore parse error
      }
      throw new ApiError(errorMsg, response.status);
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `vulnscan-report-${scanId}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(downloadUrl);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      error.message || 'Unable to download PDF report from server.',
      0,
      'NETWORK_ERROR'
    );
  }
}

/**
 * List historical scans with pagination.
 * @param {number} limit
 * @param {number} offset
 * @returns {Promise<{total: number, items: Array}>}
 */
export async function listScans(limit = 50, offset = 0) {
  try {
    const response = await fetch(
      `${API_BASE_URL}/api/scans?limit=${limit}&offset=${offset}`,
      { cache: 'no-store' }
    );
    return await handleResponse(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('Failed to fetch scan history from server.', 0, 'NETWORK_ERROR');
  }
}

/**
 * Check backend health status.
 * @returns {Promise<{status: string}>}
 */
export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    return await handleResponse(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('Backend health check unreachable.', 0, 'NETWORK_ERROR');
  }
}
