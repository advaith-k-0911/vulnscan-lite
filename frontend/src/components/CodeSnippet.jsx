import React, { useState } from 'react';

/**
 * CodeSnippet Component
 * Renders server configuration examples with multi-server tabs and one-click copy.
 *
 * @param {Object} props
 * @param {Object.<string, string>} props.snippets - Map of server name -> config code string
 */
export default function CodeSnippet({ snippets = {} }) {
  const serverKeys = Object.keys(snippets);
  const [selectedServer, setSelectedServer] = useState(serverKeys[0] || '');
  const [copied, setCopied] = useState(false);

  if (serverKeys.length === 0) return null;

  const currentCode = snippets[selectedServer] || '';

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(currentCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback if clipboard API is restricted
      setCopied(false);
    }
  };

  return (
    <div className="code-snippet-box">
      <div className="code-snippet-header">
        <div className="snippet-tabs" role="tablist" aria-label="Web server configurations">
          {serverKeys.map((server) => (
            <button
              key={server}
              role="tab"
              aria-selected={selectedServer === server}
              className={`snippet-tab-btn ${selectedServer === server ? 'active' : ''}`}
              onClick={() => setSelectedServer(server)}
            >
              {server}
            </button>
          ))}
        </div>
        <button
          type="button"
          className="copy-snippet-btn"
          onClick={handleCopy}
          aria-label={copied ? 'Copied snippet to clipboard' : `Copy ${selectedServer} configuration`}
        >
          {copied ? '✓ Copied' : '📋 Copy'}
        </button>
      </div>

      <pre className="code-pre mono" tabIndex={0}>
        <code>{currentCode}</code>
      </pre>
    </div>
  );
}
