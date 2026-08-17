import React from 'react';

export default function Footer() {
  return (
    <footer className="site-footer">
      <div className="footer-container">
        <p className="footer-disclaimer">
          <strong>Notice:</strong> Only scan websites you own or have explicit authorization to assess.
          VulnScan Lite conducts non-intrusive, passive security configuration assessments only.
        </p>
        <div className="footer-bottom">
          <span className="footer-credit">
            Developed by <strong>Advaith K</strong> — B.Tech CSE (Cyber Security)
          </span>
          <span className="footer-version">v1.0.0</span>
        </div>
      </div>
    </footer>
  );
}
