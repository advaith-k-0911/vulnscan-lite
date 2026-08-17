import React from 'react';
import { Link } from 'react-router-dom';

export default function AboutAppPage() {
  return (
    <main className="about-app-container">
      {/* Hero / Header Section */}
      <section className="about-header-section">
        <div className="hero-badge">PLATFORM ARCHITECTURE & CAPABILITIES</div>
        <h1 className="about-title">About VulnScan Lite</h1>
        <p className="about-subtitle">
          Passive Web Security & Configuration Posture Assessment Platform
        </p>
      </section>

      {/* Overview Card */}
      <section className="about-app-overview-card" aria-label="Application Summary">
        <h2 className="app-section-heading">Platform Overview</h2>
        <p className="app-overview-text">
          <strong>VulnScan Lite</strong> is a specialized, lightweight web security tool engineered to perform
          fast, non-intrusive security posture assessments on web applications. Built from the ground up to follow
          strict passive reconnaissance principles, it provides actionable security diagnostics and hardening guidance
          without active fuzzing, intrusive exploitation, or disruptive scanning methods.
        </p>
      </section>

      {/* Core Capabilities Grid */}
      <section className="capabilities-section" aria-label="Core Inspection Capabilities">
        <h2 className="app-section-heading">Key Capabilities</h2>
        <div className="capabilities-grid">
          <div className="capability-card">
            <div className="capability-icon">🛡️</div>
            <div className="capability-body">
              <h3 className="capability-title">Security Headers Audit</h3>
              <p className="capability-desc">
                Evaluates Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options,
                X-Content-Type-Options, Referrer-Policy, and Permissions-Policy with HTTPS-aware criteria.
              </p>
            </div>
          </div>

          <div className="capability-card">
            <div className="capability-icon">🔒</div>
            <div className="capability-body">
              <h3 className="capability-title">TLS / SSL Health Inspection</h3>
              <p className="capability-desc">
                Inspects certificate validity windows, expiration math, protocol versions (TLS 1.2 & 1.3),
                and cipher suite strength to safeguard cryptographic integrity.
              </p>
            </div>
          </div>

          <div className="capability-card">
            <div className="capability-icon">⚡</div>
            <div className="capability-body">
              <h3 className="capability-title">HTTP & Network Telemetry</h3>
              <p className="capability-desc">
                Measures response latency, validates redirection chains, captures HTTP status codes, and enforces
                multi-layered SSRF defenses protecting internal subnets.
              </p>
            </div>
          </div>

          <div className="capability-card">
            <div className="capability-icon">🧩</div>
            <div className="capability-body">
              <h3 className="capability-title">Passive CMS Fingerprinting</h3>
              <p className="capability-desc">
                Detects publicly visible technology footprints and CMS signatures (WordPress, Drupal, Joomla)
                with confidence level indicators.
              </p>
            </div>
          </div>

          <div className="capability-card">
            <div className="capability-icon">📊</div>
            <div className="capability-body">
              <h3 className="capability-title">Deterministic 0–100 Scoring</h3>
              <p className="capability-desc">
                Transparent scoring model with letter grades (A–F), severity-weighted point deductions, and
                anti-double-counting safeguards.
              </p>
            </div>
          </div>

          <div className="capability-card">
            <div className="capability-icon">📄</div>
            <div className="capability-body">
              <h3 className="capability-title">Executive PDF Reports</h3>
              <p className="capability-desc">
                Generates comprehensive multi-page PDF security health reports in memory using ReportLab with
                multi-server (Nginx, Apache, Caddy) remediation snippets.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Methodology & Limitations */}
      <section className="about-app-overview-card" aria-label="Assessment Methodology">
        <h2 className="app-section-heading">Assessment Policy & Boundary</h2>
        <div className="policy-block">
          <p className="app-overview-text">
            VulnScan Lite evaluates only publicly returned HTTP response headers, TLS handshake parameters,
            and public HTML markers. It deliberately omits active crawlers, fuzzers, authentication brute-forcing,
            or intrusive payload execution. All assessments are deterministic and non-disruptive to target servers.
          </p>
        </div>
      </section>

      {/* Technology Stack Card */}
      <section className="tech-stack-card" aria-label="System Architecture & Technology Stack">
        <h2 className="app-section-heading">Technology Stack</h2>
        <div className="tech-badges-grid">
          <div className="tech-badge-item">
            <span className="tech-badge-name">Frontend</span>
            <span className="tech-badge-value mono">React 18 • Vite • Vanilla CSS</span>
          </div>
          <div className="tech-badge-item">
            <span className="tech-badge-name">Backend API</span>
            <span className="tech-badge-value mono">FastAPI • Pydantic v2 • Python 3.13</span>
          </div>
          <div className="tech-badge-item">
            <span className="tech-badge-name">Task Queue</span>
            <span className="tech-badge-value mono">Celery • Redis Message Broker</span>
          </div>
          <div className="tech-badge-item">
            <span className="tech-badge-name">Database</span>
            <span className="tech-badge-value mono">SQLAlchemy 2.0 • SQLite / PostgreSQL</span>
          </div>
          <div className="tech-badge-item">
            <span className="tech-badge-name">Reporting</span>
            <span className="tech-badge-value mono">ReportLab PDF Engine</span>
          </div>
          <div className="tech-badge-item">
            <span className="tech-badge-name">Testing</span>
            <span className="tech-badge-value mono">Pytest (314 tests) • Vitest (22 tests)</span>
          </div>
        </div>

        <div className="app-cta-bar">
          <Link to="/" className="btn btn-primary">
            Start a Security Scan →
          </Link>
          <Link to="/history" className="btn btn-secondary">
            View Scan History
          </Link>
        </div>
      </section>
    </main>
  );
}
