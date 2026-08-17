# VulnScan Lite - Scanning Logic Specification

## 1. Scanner Philosophy & Safety Boundary
VulnScan Lite strictly performs **passive analysis**:
- Zero exploitation, payload injection, fuzzing, or brute forcing.
- All checks rely strictly on standard, non-intrusive network interactions (single request chains, header inspections, standard TLS handshakes, public HTML parsing).

---

## 2. Scanner Orchestration Flow (`scanner/engine.py`) — **Implemented (Phase 7)**

The unified scanner coordinates all passive security checks sequentially:

```text
Target URL
   │
   ▼
[ 1. HTTP Analysis & SSRF Guard ] ──► (Target Blocked / DNS Error) ──► FAILED Result
   │
   ├── Response Headers
   │       ↓
   │   [ 2. Security Headers Analyzer ] (Pure in-memory)
   │
   ├── TLS Handshake (if HTTPS)
   │       ↓
   │   [ 3. TLS / Certificate Inspector ]
   │
   └── HTML Response
           ↓
       [ 4. Passive CMS Fingerprinter ] (Pure in-memory)
           │
           ▼
[ 5. Finding Normalization ]
           │
           ▼
[ 6. Centralized 0-100 Scoring & Grading ]
           │
           ▼
[ 7. Remediation Guidance Attachment ]
           │
           ▼
Final JSON-Serializable Scan Result
```

---

## 3. Scanner Modules

### A. HTTP Analysis & Target Validation (`scanner/http.py`) — **Implemented (Phase 2)**

#### What It Checks:
- **URL Sanitization & Normalization**: Automatically prepends `https://` if no scheme is provided; validates protocol schemes (`http`, `https` only).
- **Multi-Tier SSRF Filtering**:
  - Rejects loopback addresses (`127.0.0.0/8`, `::1`, `localhost`).
  - Rejects RFC 1918 private IPv4 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Rejects link-local and cloud metadata addresses (`169.254.0.0/16`, `fe80::/10`, `metadata.google.internal`).
  - Rejects internal domain suffixes (`.local`, `.internal`, `.lan`, `.corp`, `.test`, `.invalid`, `.arpa`).
  - Pre-request DNS resolution & verification against all resolved IP addresses.
  - Re-evaluates destination URL against SSRF filters on **every redirect hop**.
- **HTTP Response Attributes**:
  - HTTP status code (200, 301, 302, 404, 500, etc.).
  - Response time measured in seconds (high-resolution float).
  - Exact redirect chain list and total redirect hop count.
  - Response headers dictionary.
  - Content-Type and Content-Length.
  - Safe HTML detection (evaluates `Content-Type` and body structure).
- **Defensive Resource Controls**:
  - **Timeouts**: Configurable connection and read timeouts (default: 5.0s connect, 5.0s read, 10.0s total).
  - **Redirect Limit**: Maximum 5 redirect hops before returning a controlled `REDIRECT_LIMIT` error.
  - **Response Size Cap**: Max 5 MB response body reading via streamed chunks. If body exceeds the limit, streaming stops and `truncated` is marked `True`.
- **Structured Error Codes**:
  - `INVALID_URL`: Malformed URL, unsupported scheme, missing hostname, or invalid port.
  - `BLOCKED_TARGET`: Hostname, domain, or IP belongs to a forbidden local/private/internal range.
  - `DNS_ERROR`: DNS lookup failed or yielded no valid IP addresses.
  - `CONNECTION_ERROR`: TCP connection failure or network error.
  - `TIMEOUT`: Request exceeded connect/read timeout limits.
  - `TLS_ERROR`: SSL/TLS handshake or certificate error.
  - `REDIRECT_LIMIT`: Redirect chain exceeded maximum allowed hops.
  - `UNKNOWN_ERROR`: Safe fallback for uncaught operational exceptions without stack trace leakage.

---

### B. Security Headers (`scanner/headers.py`) — **Implemented (Phase 3)**

The security headers module is a **pure analytical engine** that performs **zero network I/O**. It consumes the HTTP headers dictionary collected during Phase 2.

#### Header Checks Implemented:
1. **Content-Security-Policy (`CSP`)**:
   - `PASS`: Present and contains non-empty policy definitions.
   - `FAIL`: Header is missing (`severity: MEDIUM`, `remediation_key: content_security_policy`).
   - `WARNING`: Present but empty or whitespace-only.
2. **X-Frame-Options**:
   - `PASS`: Configured with standard protective directives: `DENY` or `SAMEORIGIN` (case-insensitive).
   - `FAIL`: Header is missing (`severity: MEDIUM`, `remediation_key: x_frame_options`).
   - `WARNING`: Uses deprecated `ALLOW-FROM` directive, unrecognized directive, or empty value.
3. **Strict-Transport-Security (`HSTS`)**:
   - **HTTPS Target**: `PASS` (valid max-age), `FAIL` (missing on HTTPS), `WARNING` (max-age=0).
   - **HTTP Target**: `INFO` (not applicable over unencrypted HTTP per RFC 6797).
4. **X-Content-Type-Options**:
   - `PASS`: Present and set to `nosniff`.
   - `FAIL`: Missing (`severity: LOW`, `remediation_key: x_content_type_options`).
5. **Referrer-Policy**:
   - `PASS`: Configured with a recognized privacy directive.
   - `FAIL`: Missing (`severity: LOW`, `remediation_key: referrer_policy`).
6. **Permissions-Policy**:
   - `PASS`: Present and non-empty.
   - `FAIL`: Missing (`severity: LOW`, `remediation_key: permissions_policy`).
   - `WARNING`: Empty value or using legacy `Feature-Policy`.

---

### C. TLS / SSL Analysis (`scanner/tls.py`) — **Implemented (Phase 4)**

Performs passive SSL/TLS certificate and connection inspection using Python's standard `ssl` module.
- Validates certificate trust roots and hostname matching (`check_hostname = True`, `CERT_REQUIRED`).
- Evaluates expiration: $>30$ days (PASS), $\le 30$ days (WARNING), expired/invalid (FAIL).
- Evaluates protocol versions: TLS 1.2 / 1.3 (PASS), TLS 1.0 / 1.1 (WARNING), SSLv3 (FAIL).
- Classifies cipher strength: `strong`, `moderate`, `weak`, `unknown`.
- Plain HTTP targets return `supported: false, status: INFO` safely.

---

### D. Passive CMS Detection (`scanner/cms.py`) — **Implemented (Phase 5)**

Performs purely passive fingerprinting of Content Management Systems (WordPress, Drupal, Joomla) using previously retrieved HTML and headers.
- Zero network requests and zero probing of administrative routes (`/wp-admin`, `/wp-login.php`, `/xmlrpc.php`).
- Extracts generator metadata, theme/module paths, inline DOM signatures, and response headers.
- Evaluates confidence: `HIGH`, `MEDIUM`, `LOW`.
- Safely reports explicit versions when publicly disclosed.

---

### E. Deterministic Scoring Engine (`scanner/scoring.py`) — **Implemented (Phase 6)**

- **Starting Score**: `100` points (bounded in `[0, 100]`).
- **Grading Scale**:
  - `90 - 100`: Grade **A**
  - `80 - 89`: Grade **B**
  - `70 - 79`: Grade **C**
  - `60 - 69`: Grade **D**
  - `0 - 59`: Grade **F**
- **Deductions**:
  - Missing HTTPS: `-20`
  - Invalid/Expired TLS Certificate: `-15` (Expiring soon: `-5`)
  - Obsolete TLS / SSL: `-5` to `-10`
  - Weak / Moderate Cipher: `-3` to `-10`
  - Missing Security Headers (CSP, XFO, HSTS, XCTO, RP, PP): `-5` to `-10`
  - CMS Footprint: `0` (informational only).
- **Anti-Double-Counting**: Plain HTTP targets are penalized `-20` once without compounding non-applicable TLS/HSTS penalties.

---

### F. Remediation Guidance (`scanner/remediation.py`) — **Implemented (Phase 6)**

Provides vendor-neutral remediation guidance, technical explanations, browser implications, and practical configuration snippets for Nginx, Apache, Caddy, and Certbot.
