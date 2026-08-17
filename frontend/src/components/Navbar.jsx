import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export default function Navbar() {
  const location = useLocation();

  return (
    <header className="site-header">
      <div className="header-container">
        <div className="brand-section">
          <Link to="/" className="brand-link" aria-label="VulnScan Lite Home">
            <span className="brand-name">VulnScan Lite</span>
          </Link>
          <span className="brand-tag">PASSIVE AUDIT</span>
        </div>

        <nav className="nav-links" aria-label="Main Navigation">
          <Link
            to="/"
            className={`nav-link ${location.pathname === '/' || location.pathname === '/scan' ? 'active' : ''}`}
          >
            Scanner
          </Link>
          <Link
            to="/history"
            className={`nav-link ${location.pathname === '/history' ? 'active' : ''}`}
          >
            Scan History
          </Link>
          <Link
            to="/about-app"
            className={`nav-link ${location.pathname === '/about-app' ? 'active' : ''}`}
          >
            About App
          </Link>
          <Link
            to="/about"
            className={`nav-link ${location.pathname === '/about' ? 'active' : ''}`}
          >
            About Developer
          </Link>
        </nav>

        <div className="header-meta">
          <span className="dev-credit">Dev: Advaith K</span>
        </div>
      </div>
    </header>
  );
}
