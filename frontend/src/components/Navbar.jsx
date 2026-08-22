import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';

export default function Navbar() {
  const location = useLocation();
  const [isOpen, setIsOpen] = useState(false);

  // Close menu on route transition
  useEffect(() => {
    setIsOpen(false);
  }, [location.pathname]);

  // Close menu on Escape key press
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setIsOpen(false);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const toggleMenu = () => setIsOpen((prev) => !prev);
  const closeMenu = () => setIsOpen(false);

  return (
    <header className="site-header">
      <div className="header-container">
        <div className="brand-section">
          <Link to="/" className="brand-link" aria-label="VulnScan Lite Home" onClick={closeMenu}>
            <span className="brand-name">VulnScan Lite</span>
          </Link>
          <span className="brand-tag">PASSIVE AUDIT</span>
        </div>

        {/* Mobile Hamburger / Close Toggle Button */}
        <button
          type="button"
          className="mobile-nav-toggle"
          onClick={toggleMenu}
          aria-expanded={isOpen}
          aria-controls="primary-navigation"
          aria-label={isOpen ? 'Close navigation menu' : 'Open navigation menu'}
        >
          {isOpen ? (
            <span className="toggle-icon close-icon" aria-hidden="true">✕</span>
          ) : (
            <span className="toggle-icon hamburger-icon" aria-hidden="true">☰</span>
          )}
        </button>

        {/* Navigation Links */}
        <nav
          id="primary-navigation"
          className={`nav-links ${isOpen ? 'mobile-open' : ''}`}
          aria-label="Main Navigation"
        >
          <Link
            to="/"
            onClick={closeMenu}
            className={`nav-link ${location.pathname === '/' || location.pathname === '/scan' ? 'active' : ''}`}
          >
            Scanner
          </Link>
          <Link
            to="/history"
            onClick={closeMenu}
            className={`nav-link ${location.pathname === '/history' ? 'active' : ''}`}
          >
            Scan History
          </Link>
          <Link
            to="/about-app"
            onClick={closeMenu}
            className={`nav-link ${location.pathname === '/about-app' ? 'active' : ''}`}
          >
            About App
          </Link>
          <Link
            to="/about"
            onClick={closeMenu}
            className={`nav-link ${location.pathname === '/about' ? 'active' : ''}`}
          >
            About Developer
          </Link>

          <div className="mobile-dev-credit">
            <span className="dev-credit">Dev: Advaith K</span>
          </div>
        </nav>

        <div className="header-meta desktop-only">
          <span className="dev-credit">Dev: Advaith K</span>
        </div>
      </div>
    </header>
  );
}
