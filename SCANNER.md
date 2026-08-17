# VulnScan Lite - Scanner Engine & Inspection Logic Reference

---

## 1. Scanner Philosophy & Safety Boundary

VulnScan Lite is strictly a **passive security configuration scanner**:
- **Zero Exploitation**: Never sends SQL injection, XSS payloads, or active exploit attempts.
- **Zero Fuzzing**: Never performs directory brute-forcing, parameter discovery, or credential spraying.
- **Single-Chain Interaction**: Executes a single bounded HTTP/HTTPS request chain and TLS handshake to inspect public configuration metadata.
- **Non-Disruptive**: Safe for continuous monitoring and configuration health checks on authorized targets.

---

## 2. Orchestration Pipeline (`scanner/engine.py`)

The scanner orchestrates all passive analysis stages sequentially:

```text
                     Target Website URL
                             │
                             ▼
              [ 1. HTTP Analysis & SSRF Guard ] 
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
  [ 2. Headers ]       [ 3. TLS / SSL ]   [ 4. CMS Engine ]
  (Analyzes CSP,      (Handshake, Cert,   (Passive HTML
   HSTS, XFO, etc.)    TLS 1.2/1.3, Ciphers) Meta & Signatures)
          │                  │                  │
          └──────────────────┬──────────────────┘
                             ▼
              [ 5. Finding Normalization ]
                             │
                             ▼
             [ 6. 0–100 Scoring & Grading Engine ]
                             │
                             ▼
             [ 7. Remediation Guidance Engine ]
                             │
                             ▼
              Standardized JSON Scan Result
```

---

## 3. Scanner Modules Deep-Dive

### A. HTTP & SSRF Protection Engine (`scanner/http.py`)
- **Purpose**: Establishes controlled HTTP/HTTPS connections and extracts network metadata while strictly preventing Server-Side Request Forgery (SSRF).
- **Target URL Normalization**: Validates scheme (`http://` or `https://`), trims whitespace, limits length to 2,048 characters.
- **SSRF Filtering Guardrails**:
  - Rejects loopback addresses (`127.0.0.0/8`, `::1`, `localhost`).
  - Rejects RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Rejects link-local and cloud metadata addresses (`169.254.0.0/16`, `fe80::/10`, `metadata.google.internal`).
  - Rejects IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`).
  - Rejects internal TLD suffixes (`.local`, `.internal`, `.lan`, `.corp`, `.test`, `.invalid`, `.arpa`).
  - Enforces pre-request DNS resolution checking all resolved IPs.
  - Re-evaluates destination IP against SSRF filters on **every redirect hop**.
- **Operational Bounds**:
  - Connection & Read Timeout: 10 seconds.
  - Maximum Redirect Hops: 5 hops.
  - Maximum Response Size: 5 MB (streamed chunks truncated safely).

---

### B. Security Headers Inspector (`scanner/headers.py`)
- **Purpose**: Analyzes HTTP response headers to identify missing or weak defensive directives (zero network I/O).
- **Headers Evaluated**:
  1. **Content-Security-Policy (CSP)**:
     - `PASS`: Present with valid directive strings.
     - `FAIL` (-10 pts): Header missing (vulnerable to XSS / clickjacking).
     - `WARNING` (-5 pts): Present but empty or contains unsafe wildcards.
  2. **Strict-Transport-Security (HSTS)**:
     - `PASS`: Present on HTTPS target with `max-age` >= 10886400 (18 weeks).
     - `FAIL` (-10 pts): Missing on HTTPS target.
     - `INFO`: Not applicable over unencrypted HTTP.
  3. **X-Frame-Options (XFO)**:
     - `PASS`: Present with `DENY` or `SAMEORIGIN`.
     - `FAIL` (-10 pts): Missing (vulnerable to clickjacking / frame embedding).
     - `WARNING` (-5 pts): Present with deprecated `ALLOW-FROM`.
  4. **X-Content-Type-Options (XCTO)**:
     - `PASS`: Set to `nosniff`.
     - `FAIL` (-5 pts): Missing or invalid (MIME-type sniffing risk).
  5. **Referrer-Policy**:
     - `PASS`: Present with restrictive directive (`strict-origin-when-cross-origin`, `no-referrer`, `same-origin`).
     - `FAIL` (-5 pts): Missing (potential URL parameter / referrer leakage).
  6. **Permissions-Policy**:
     - `PASS`: Present and defines browser feature restrictions.
     - `WARNING` (-5 pts): Missing (camera, microphone, geolocation unconstrained).

---

### C. TLS / SSL Inspection Engine (`scanner/tls.py`)
- **Purpose**: Inspects cryptographic parameters and certificate validity via standard SSL socket handshakes.
- **Checks Evaluated**:
  1. **Certificate Expiration & Validity**:
     - `PASS`: Valid certificate with > 30 days remaining.
     - `WARNING` (-5 pts): Expiring within 30 days.
     - `FAIL` (-15 pts): Expired certificate or invalid hostname mismatch.
  2. **TLS Protocol Version**:
     - `PASS`: Enforces modern TLS 1.2 or TLS 1.3.
     - `FAIL` (-15 pts): Outdated protocol negotiated (TLS 1.0 / 1.1 or SSLv3).
  3. **Cipher Suite Cryptographic Strength**:
     - `PASS`: Strong modern cipher suite (e.g., `TLS_AES_256_GCM_SHA384`, `ECDHE-RSA-AES128-GCM-SHA256`).
     - `WARNING` (-5 pts): CBC-mode cipher or 128-bit key exchange.
     - `FAIL` (-15 pts): Null, export, RC4, or DES cipher suite.

---

### D. Passive CMS Fingerprinter (`scanner/cms.py`)
- **Purpose**: Detects public technology markers without sending active probes or fuzzing admin directories.
- **Signatures Evaluated**:
  - Meta generator tags (`<meta name="generator" content="WordPress 6.4">`).
  - Distinctive HTML script/stylesheet paths (`/wp-content/`, `/sites/default/files/`, `/media/jui/`).
  - Response headers (`X-Powered-By`, `X-Generator`).
- **Supported CMS**: **WordPress**, **Drupal**, **Joomla**.

---

## 4. Deterministic Scoring Algorithm (`scanner/scoring.py`)

### Mathematical Foundation:
1. Every scan begins with a baseline score of **100**.
2. Point deductions are subtracted based on finding severity:
   - **CRITICAL**: `-25 points`
   - **HIGH**: `-15 points`
   - **MEDIUM**: `-10 points`
   - **LOW**: `-5 points`
   - **WARNING**: `-5 points`
   - **INFO / PASS**: `0 points`
3. Non-applicable checks (e.g. HSTS over plain HTTP) carry **0 points** deduction.
4. **Bounds Clamping**: The computed score is strictly bounded within `[0, 100]`.
5. **Letter Grade Thresholds**:
   - **Grade A**: `90 – 100` (Excellent security posture)
   - **Grade B**: `80 – 89` (Good posture, minor configuration improvements recommended)
   - **Grade C**: `70 – 79` (Moderate posture, key security headers or TLS settings missing)
   - **Grade D**: `60 – 69` (Poor posture, critical defensive controls absent)
   - **Grade F**: `0 – 59` (Critical configuration defects or broken cryptography)

---

## 5. Actionable Remediation Guidance (`scanner/remediation.py`)

Every non-passing finding attaches structured, copy-pasteable remediation:
1. **Why It Matters**: Technical risk rationale explaining the underlying vulnerability.
2. **Recommended Action**: Clear instructions for security hardening.
3. **Configuration Examples**: Server recipes for:
   - **Nginx** (`add_header ...`)
   - **Apache** (`Header always set ...`)
   - **Caddy** (`header ...`)
