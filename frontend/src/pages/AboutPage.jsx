import React from 'react';
import { Link } from 'react-router-dom';

export default function AboutPage() {
  return (
    <main className="about-page-container">
      {/* Header Section */}
      <section className="about-header-section">
        <h1 className="about-title">About the Developer</h1>
        <p className="about-subtitle">
          The creator and security architect behind VulnScan Lite.
        </p>
      </section>

      {/* Developer Profile Card */}
      <section className="about-profile-card" aria-label="Developer Information Card">
        <div className="profile-badge-strip">
          <span className="profile-role-badge">PROJECT ARCHITECT</span>
        </div>

        <div className="profile-details-block">
          <h2 className="profile-name">Advaith K</h2>
          <p className="profile-degree">B.Tech CSE (Cyber Security) Student</p>
        </div>

        <div className="profile-bio-text">
          <p>
            VulnScan Lite was designed and built as a lightweight, passive web security health scanner.
            The goal is to provide developers, administrators, and security analysts with clear, deterministic
            visibility into their HTTP configuration, TLS parameters, and security headers without invasive probing.
          </p>
        </div>

        {/* Horizontal Social Buttons Container */}
        <div className="developer-social-panel" aria-label="Developer Profiles">
          {/* LinkedIn Button Item */}
          <a
            href="https://www.linkedin.com/in/advaith-k-21jul2006"
            target="_blank"
            rel="noopener noreferrer"
            className="social-button-item"
            aria-label="Visit Advaith K's LinkedIn profile (opens in a new tab)"
          >
            <div className="social-button-content">
              <svg className="social-platform-icon" viewBox="0 0 24 24" width="24" height="24" aria-hidden="true">
                <rect width="24" height="24" rx="4" fill="#FFD700" />
                <path fill="#000000" d="M7.1 9.4H4.7v8.9h2.4V9.4zM5.9 5.7c-.8 0-1.4.6-1.4 1.4s.6 1.4 1.4 1.4 1.4-.6 1.4-1.4-.6-1.4-1.4-1.4zm13.4 6.7c0-2.4-1.3-3.6-3-3.6-1.4 0-2.1.8-2.4 1.4V9.4h-2.4v8.9h2.4v-4.9c0-1.3.2-2.5 1.8-2.5 1.6 0 1.6 1.5 1.6 2.6v4.8h2.4v-5.9z" />
              </svg>
              <span className="social-button-label">LinkedIn</span>
            </div>
            <svg className="external-link-arrow" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#FFD700" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
              <polyline points="15 3 21 3 21 9"></polyline>
              <line x1="10" y1="14" x2="21" y2="3"></line>
            </svg>
          </a>

          {/* Center Divider */}
          <div className="social-divider" aria-hidden="true"></div>

          {/* GitHub Button Item */}
          <a
            href="https://github.com/advaith-k-0911/vulnscan-lite"
            target="_blank"
            rel="noopener noreferrer"
            className="social-button-item"
            aria-label="Visit Advaith K's GitHub profile (opens in a new tab)"
          >
            <div className="social-button-content">
              <svg className="social-platform-icon" viewBox="0 0 24 24" width="24" height="24" aria-hidden="true">
                <path fill="#FFD700" fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
              <span className="social-button-label">GitHub</span>
            </div>
            <svg className="external-link-arrow" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#FFD700" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
              <polyline points="15 3 21 3 21 9"></polyline>
              <line x1="10" y1="14" x2="21" y2="3"></line>
            </svg>
          </a>
        </div>

        <div className="profile-actions-strip">
          <Link to="/" className="btn btn-primary">
            Open Scanner →
          </Link>
        </div>
      </section>
    </main>
  );
}
