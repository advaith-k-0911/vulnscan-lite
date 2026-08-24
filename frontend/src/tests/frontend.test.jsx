import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter, MemoryRouter, Routes, Route } from 'react-router-dom';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import * as api from '../services/api';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import ScanStatus from '../components/ScanStatus';
import ScanProgress from '../components/ScanProgress';
import ScoreGauge from '../components/ScoreGauge';
import CodeSnippet from '../components/CodeSnippet';
import FindingCard from '../components/FindingCard';
import ScannerPage from '../pages/ScannerPage';
import ResultPage from '../pages/ResultPage';
import HistoryPage from '../pages/HistoryPage';
import AboutPage from '../pages/AboutPage';
import AboutAppPage from '../pages/AboutAppPage';

describe('Navbar Component', () => {
  it('renders links to Scanner, Scan History, About App, and About Developer pages', () => {
    render(
      <BrowserRouter>
        <Navbar />
      </BrowserRouter>
    );

    const scannerLink = screen.getByRole('link', { name: 'Scanner' });
    const historyLink = screen.getByRole('link', { name: 'Scan History' });
    const aboutAppLink = screen.getByRole('link', { name: 'About App' });
    const aboutDevLink = screen.getByRole('link', { name: 'About Developer' });

    expect(scannerLink.getAttribute('href')).toBe('/');
    expect(historyLink.getAttribute('href')).toBe('/history');
    expect(aboutAppLink.getAttribute('href')).toBe('/about-app');
    expect(aboutDevLink.getAttribute('href')).toBe('/about');
    expect(screen.getAllByText('Dev: Advaith K').length).toBeGreaterThan(0);
  });

  it('toggles mobile menu open and close states with button interaction', () => {
    render(
      <BrowserRouter>
        <Navbar />
      </BrowserRouter>
    );

    const toggleBtn = screen.getByRole('button', { name: /Open navigation menu/i });
    expect(toggleBtn.getAttribute('aria-expanded')).toBe('false');

    fireEvent.click(toggleBtn);
    expect(toggleBtn.getAttribute('aria-expanded')).toBe('true');

    fireEvent.click(toggleBtn);
    expect(toggleBtn.getAttribute('aria-expanded')).toBe('false');
  });
});

describe('Footer Component', () => {
  it('renders footer copyright, safety disclaimer, and developer attribution', () => {
    render(
      <BrowserRouter>
        <Footer />
      </BrowserRouter>
    );

    expect(screen.getByText(/VulnScan Lite/i)).toBeDefined();
    expect(screen.getByText(/Advaith K/i)).toBeDefined();
    expect(screen.getByText(/B.Tech CSE/i)).toBeDefined();
    expect(screen.getByText(/Only scan websites you own/i)).toBeDefined();
  });
});

describe('ScannerPage Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders clean scan form without removed assessment boundary section', () => {
    render(
      <BrowserRouter>
        <ScannerPage />
      </BrowserRouter>
    );

    expect(screen.getByText('VulnScan Lite')).toBeDefined();
    expect(screen.getByPlaceholderText('https://example.com')).toBeDefined();
    expect(screen.getByRole('button', { name: /Start Scan/i })).toBeDefined();

    // Verify Assessment Boundary section was removed
    expect(screen.queryByText('Assessment Boundary')).toBeNull();
  });

  it('displays safe rate limiting error message on 429 Too Many Requests response', async () => {
    vi.spyOn(api, 'createScan').mockRejectedValue(
      new api.ApiError('Too many scan requests. Please wait and try again.', 429, 'RATE_LIMITED')
    );

    render(
      <BrowserRouter>
        <ScannerPage />
      </BrowserRouter>
    );

    const input = screen.getByPlaceholderText('https://example.com');
    const submitBtn = screen.getByRole('button', { name: /Start Scan/i });

    fireEvent.change(input, { target: { value: 'https://example.com' } });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/Too many scan requests/i)).toBeDefined();
    });
  });

  it('disables submit button when target URL input is empty to prevent blank submission', () => {
    const createSpy = vi.spyOn(api, 'createScan');

    render(
      <BrowserRouter>
        <ScannerPage />
      </BrowserRouter>
    );

    const submitBtn = screen.getByRole('button', { name: /Start Scan/i });
    expect(submitBtn.disabled).toBe(true);

    fireEvent.click(submitBtn);
    expect(createSpy).not.toHaveBeenCalled();
  });
});

describe('AboutPage Component', () => {
  it('renders developer name, degree, and button-style social links without raw URL strings', () => {
    render(
      <BrowserRouter>
        <AboutPage />
      </BrowserRouter>
    );

    expect(screen.getByText('About the Developer')).toBeDefined();
    expect(screen.getByText('Advaith K')).toBeDefined();
    expect(screen.getByText('B.Tech CSE (Cyber Security) Student')).toBeDefined();

    const linkedinLink = screen.getByRole('link', { name: /LinkedIn/i });
    const githubLink = screen.getByRole('link', { name: /GitHub/i });

    expect(linkedinLink.getAttribute('href')).toBe('https://www.linkedin.com/in/advaith-k-21jul2006');
    expect(linkedinLink.getAttribute('rel')).toBe('noopener noreferrer');
    expect(linkedinLink.getAttribute('target')).toBe('_blank');
    expect(screen.getByText('LinkedIn')).toBeDefined();

    expect(githubLink.getAttribute('href')).toBe('https://github.com/advaith-k-0911/vulnscan-lite');
    expect(githubLink.getAttribute('rel')).toBe('noopener noreferrer');
    expect(githubLink.getAttribute('target')).toBe('_blank');
    expect(screen.getByText('GitHub')).toBeDefined();

    // Verify raw url text strings are not displayed
    expect(screen.queryByText('https://www.linkedin.com/in/advaith-k-21jul2006')).toBeNull();
    expect(screen.queryByText('https://github.com/advaith-k-0911/vulnscan-lite')).toBeNull();
  });
});

describe('AboutAppPage Component', () => {
  it('renders architecture specifications, passive inspection modules, and PDF section', () => {
    render(
      <BrowserRouter>
        <AboutAppPage />
      </BrowserRouter>
    );

    expect(screen.getByText('About VulnScan Lite')).toBeDefined();
    expect(screen.getByText('Key Capabilities')).toBeDefined();
    expect(screen.getByText('Security Headers Audit')).toBeDefined();
    expect(screen.getByText('TLS / SSL Health Inspection')).toBeDefined();
    expect(screen.getByText('Deterministic 0–100 Scoring')).toBeDefined();
    expect(screen.getByText('Executive PDF Reports')).toBeDefined();
    expect(screen.getByText('Technology Stack')).toBeDefined();
  });
});

describe('ScanStatus Component', () => {
  it('renders status badges with appropriate styles for QUEUED, RUNNING, COMPLETED, FAILED', () => {
    const { rerender } = render(<ScanStatus status="QUEUED" />);
    expect(screen.getByText('Queued')).toBeDefined();

    rerender(<ScanStatus status="RUNNING" />);
    expect(screen.getByText('Scanning')).toBeDefined();

    rerender(<ScanStatus status="COMPLETED" />);
    expect(screen.getByText('Completed')).toBeDefined();

    rerender(<ScanStatus status="FAILED" />);
    expect(screen.getByText('Failed')).toBeDefined();
  });
});

describe('ScanProgress Component', () => {
  it('renders progress states, target URL, and execution indicators', () => {
    render(
      <BrowserRouter>
        <ScanProgress
          scanId="test-scan-123"
          targetUrl="https://example.com"
          status="RUNNING"
          startedAt="2026-08-17T10:00:00Z"
        />
      </BrowserRouter>
    );

    expect(screen.getByText('SCAN TARGET')).toBeDefined();
    expect(screen.getByText('example.com')).toBeDefined();
    expect(screen.getByText('https://example.com')).toBeDefined();
    expect(screen.getByText('Security scan in progress')).toBeDefined();
    expect(screen.getByText('test-scan-123')).toBeDefined();
    expect(screen.getByText(/Live status polling/i)).toBeDefined();
  });

  it('renders completed state with Scan Completed heading, score summary, and View Results action', () => {
    render(
      <BrowserRouter>
        <ScanProgress
          scanId="test-scan-complete-456"
          targetUrl="https://example.com"
          status="COMPLETED"
          scanData={{ score: 95, grade: 'A' }}
        />
      </BrowserRouter>
    );

    expect(screen.getByText('Scan Completed')).toBeDefined();
    expect(screen.getByText(/Security assessment completed successfully/i)).toBeDefined();
    expect(screen.getByText(/95\/100/i)).toBeDefined();
    expect(screen.getByText(/Grade A/i)).toBeDefined();

    const viewBtn = screen.getByRole('link', { name: /View Full Results/i });
    expect(viewBtn.getAttribute('href')).toBe('/results/test-scan-complete-456');
  });

  it('renders failed state with error message and action buttons', () => {
    const mockRetry = vi.fn();
    const mockReset = vi.fn();

    render(
      <BrowserRouter>
        <ScanProgress
          scanId="test-scan-fail-789"
          targetUrl="https://example.com"
          status="FAILED"
          error="DNS resolution failed for target host."
          onRetry={mockRetry}
          onReset={mockReset}
        />
      </BrowserRouter>
    );

    expect(screen.getByText('Scan could not be completed')).toBeDefined();
    expect(screen.getByText('DNS resolution failed for target host.')).toBeDefined();

    const tryAgainBtn = screen.getByRole('button', { name: /Try Again/i });
    const scanAnotherBtn = screen.getByRole('button', { name: /Scan Another Website/i });

    fireEvent.click(tryAgainBtn);
    expect(mockRetry).toHaveBeenCalledTimes(1);

    fireEvent.click(scanAnotherBtn);
    expect(mockReset).toHaveBeenCalledTimes(1);
  });
});

describe('ScoreGauge Component', () => {
  it('renders numeric score, letter grade, and accessibility aria-label', () => {
    render(<ScoreGauge score={85} grade="B" />);

    expect(screen.getByText('85')).toBeDefined();
    expect(screen.getByText('/ 100')).toBeDefined();
    expect(screen.getByText('B')).toBeDefined();
    expect(screen.getByRole('img', { name: /Security score: 85 out of 100, Grade B/i })).toBeDefined();
  });
});

describe('CodeSnippet Component', () => {
  it('renders multi-server configuration tabs and code snippet with copy interaction', () => {
    const mockSnippets = {
      Nginx: 'add_header X-Frame-Options "DENY" always;',
      Apache: 'Header always set X-Frame-Options "DENY"',
      Caddy: 'header X-Frame-Options "DENY"',
    };

    render(<CodeSnippet snippets={mockSnippets} />);

    expect(screen.getByText('Nginx')).toBeDefined();
    expect(screen.getByText('Apache')).toBeDefined();
    expect(screen.getByText('Caddy')).toBeDefined();
    expect(screen.getByText('add_header X-Frame-Options "DENY" always;')).toBeDefined();

    const apacheTab = screen.getByRole('tab', { name: 'Apache' });
    fireEvent.click(apacheTab);

    expect(screen.getByText('Header always set X-Frame-Options "DENY"')).toBeDefined();
  });
});

describe('FindingCard Component', () => {
  it('renders finding details, status badges, points, and expandable remediation drawer', () => {
    const mockFinding = {
      id: 'HDR_CSP',
      name: 'Content-Security-Policy Header',
      category: 'security_headers',
      status: 'FAIL',
      severity: 'MEDIUM',
      points: -10,
      description: 'Restricts sources of content loaded on the page.',
      details: 'Missing Content-Security-Policy header in HTTP response.',
      remediation: {
        why_it_matters: 'Mitigates Cross-Site Scripting (XSS) attacks.',
        recommendation: 'Define a strict policy with default-src.',
        configuration_examples: {
          Nginx: 'add_header Content-Security-Policy "default-src \'self\';" always;',
        },
      },
    };

    render(<FindingCard finding={mockFinding} />);

    expect(screen.getByText('Content-Security-Policy Header')).toBeDefined();
    expect(screen.getByText('✕ Fail')).toBeDefined();
    expect(screen.getByText('MEDIUM')).toBeDefined();
    expect(screen.getByText('-10 pts')).toBeDefined();
    expect(screen.getByText('Missing Content-Security-Policy header in HTTP response.')).toBeDefined();

    const toggleBtn = screen.getByRole('button', { name: /How to Remediate/i });
    fireEvent.click(toggleBtn);

    expect(screen.getByText('Technical Rationale & Risk')).toBeDefined();
    expect(screen.getByText('Mitigates Cross-Site Scripting (XSS) attacks.')).toBeDefined();
    expect(screen.getByText('Recommended Action')).toBeDefined();
    expect(screen.getByText('Define a strict policy with default-src.')).toBeDefined();
  });
});

describe('ResultPage Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const mockScanDetail = {
    id: 'scan-uuid-full-1',
    target_url: 'https://example.com',
    status: 'COMPLETED',
    score: 85,
    grade: 'B',
    created_at: '2026-08-17T10:00:00Z',
    started_at: '2026-08-17T10:00:01Z',
    completed_at: '2026-08-17T10:00:03Z',
    result: {
      summary: { total: 2, passed: 1, failed: 1, warnings: 0 },
      http: { status_code: 200, response_time: 0.2 },
      tls: { status: 'PASS', connection: { cipher_suite: 'TLS_AES_256_GCM_SHA384' } },
      cms: { detected: false },
      findings: [
        {
          id: 'HDR_CSP',
          name: 'Content-Security-Policy Header',
          category: 'security_headers',
          status: 'FAIL',
          severity: 'MEDIUM',
          points: -10,
          description: 'Restricts content sources.',
          details: 'Header missing',
          remediation: {
            why_it_matters: 'Mitigates XSS attacks.',
            recommendation: 'Add CSP header.',
            configuration_examples: { Nginx: 'add_header CSP;' },
          },
        },
        {
          id: 'TLS_CERT',
          name: 'TLS Certificate Validity',
          category: 'tls',
          status: 'PASS',
          severity: 'INFO',
          points: 0,
          description: 'Valid certificate.',
          details: 'Valid for 80 days.',
          remediation: null,
        },
      ],
    },
  };

  it('renders completed scan results with ScoreGauge and downloadable PDF button', async () => {
    vi.spyOn(api, 'getScan').mockResolvedValue(mockScanDetail);

    render(
      <MemoryRouter initialEntries={['/results/scan-uuid-full-1']}>
        <Routes>
          <Route path="/results/:scanId" element={<ResultPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 1, name: 'example.com' })).toBeDefined();
      expect(screen.getByText('85')).toBeDefined();
      expect(screen.getByRole('heading', { level: 3, name: 'Content-Security-Policy Header' })).toBeDefined();
      expect(screen.getByRole('button', { name: /Download executive PDF security report/i })).toBeDefined();
      expect(screen.getByRole('link', { name: /Back to Scanner/i })).toBeDefined();
    });
  });

  it('filters findings by category pill', async () => {
    vi.spyOn(api, 'getScan').mockResolvedValue(mockScanDetail);

    render(
      <MemoryRouter initialEntries={['/results/scan-uuid-full-1']}>
        <Routes>
          <Route path="/results/:scanId" element={<ResultPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 3, name: 'Content-Security-Policy Header' })).toBeDefined();
    });

    const tlsPill = screen.getByRole('button', { name: 'TLS / SSL' });
    fireEvent.click(tlsPill);

    expect(screen.getByRole('heading', { level: 3, name: 'TLS Certificate Validity' })).toBeDefined();
    expect(screen.queryByRole('heading', { level: 3, name: 'Content-Security-Policy Header' })).toBeNull();
  });

  it('handles 404 scan not found error safely', async () => {
    vi.spyOn(api, 'getScan').mockRejectedValue(
      new api.ApiError('Scan with ID "unknown" was not found.', 404, 'NOT_FOUND')
    );

    render(
      <MemoryRouter initialEntries={['/results/unknown']}>
        <Routes>
          <Route path="/results/:scanId" element={<ResultPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Scan with ID "unknown" was not found/i)).toBeDefined();
      expect(screen.getByRole('link', { name: /Back to Scanner/i })).toBeDefined();
    });
  });
});

describe('HistoryPage Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const mockHistoryList = {
    total: 2,
    items: [
      {
        id: 'scan-hist-1',
        target_url: 'https://example.com',
        status: 'COMPLETED',
        score: 90,
        grade: 'A',
        created_at: '2026-08-17T11:00:00Z',
        started_at: '2026-08-17T11:00:01Z',
        completed_at: '2026-08-17T11:00:03Z',
      },
      {
        id: 'scan-hist-2',
        target_url: 'https://insecure-site.com',
        status: 'FAILED',
        score: null,
        grade: null,
        created_at: '2026-08-17T10:30:00Z',
        started_at: '2026-08-17T10:30:01Z',
        completed_at: '2026-08-17T10:30:02Z',
      },
    ],
  };

  it('renders scan history records from database', async () => {
    vi.spyOn(api, 'listScans').mockResolvedValue(mockHistoryList);

    render(
      <BrowserRouter>
        <HistoryPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Scan History')).toBeDefined();
      expect(screen.getByText('example.com')).toBeDefined();
      expect(screen.getByText('90 / 100')).toBeDefined();
      expect(screen.getByText('A')).toBeDefined();
      expect(screen.getByText('insecure-site.com')).toBeDefined();
      expect(screen.getByRole('link', { name: /View Report/i })).toBeDefined();
    });
  });

  it('renders empty state when no scans exist in database', async () => {
    vi.spyOn(api, 'listScans').mockResolvedValue({ total: 0, items: [] });

    render(
      <BrowserRouter>
        <HistoryPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('No Scans Recorded')).toBeDefined();
      expect(screen.getByRole('link', { name: /Start Your First Scan/i })).toBeDefined();
    });
  });

  it('handles pagination next and previous controls', async () => {
    const listSpy = vi.spyOn(api, 'listScans').mockResolvedValue({
      total: 15,
      items: mockHistoryList.items,
    });

    render(
      <BrowserRouter>
        <HistoryPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Page 1 of 2/i)).toBeDefined();
    });

    const nextBtn = screen.getByRole('button', { name: /Next/i });
    fireEvent.click(nextBtn);

    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledWith(10, 10);
    });
  });
});

describe('API Service Unit Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('does not hardcode a hosted production backend fallback', async () => {
    const source = await readFile(resolve(process.cwd(), 'src/services/api.js'), 'utf8');
    expect(source).not.toContain('vulnscan-backend-1bpp.onrender.com');
  });

  it('createScan issues POST request and handles 202 response', async () => {
    const mockResponse = {
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => ({ scan_id: 'scan-123', status: 'QUEUED', message: 'Scan queued' }),
    };
    global.fetch = vi.fn().mockResolvedValue(mockResponse);

    const result = await api.createScan('https://example.com');
    expect(result.scan_id).toBe('scan-123');
    expect(result.status).toBe('QUEUED');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/scans'),
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('getScanStatus issues GET request and returns status payload', async () => {
    const mockResponse = {
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => ({ scan_id: 'scan-123', status: 'RUNNING' }),
    };
    global.fetch = vi.fn().mockResolvedValue(mockResponse);

    const result = await api.getScanStatus('scan-123');
    expect(result.status).toBe('RUNNING');
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/scans/scan-123/status'),
      { cache: 'no-store' }
    );
  });

  it('checkHealth issues GET request to /health', async () => {
    const mockResponse = {
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => ({ status: 'healthy' }),
    };
    global.fetch = vi.fn().mockResolvedValue(mockResponse);

    const result = await api.checkHealth();
    expect(result.status).toBe('healthy');
  });

  it('downloadScanPdf generates a temporary blob download URL and cleans up', async () => {
    const mockBlob = new Blob(['%PDF-1.4 test'], { type: 'application/pdf' });
    const mockResponse = {
      ok: true,
      headers: { get: () => 'application/pdf' },
      blob: async () => mockBlob,
    };
    global.fetch = vi.fn().mockResolvedValue(mockResponse);
    window.URL.createObjectURL = vi.fn().mockReturnValue('blob:http://localhost/test-uuid');
    window.URL.revokeObjectURL = vi.fn();
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    await api.downloadScanPdf('test-scan-123');
    expect(window.URL.createObjectURL).toHaveBeenCalledWith(mockBlob);
    expect(window.URL.revokeObjectURL).toHaveBeenCalledWith('blob:http://localhost/test-uuid');
    expect(clickSpy).toHaveBeenCalled();
    clickSpy.mockRestore();
  });
});
