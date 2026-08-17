# VulnScan Lite - Security Model & Hardening Policy

---

## 1. Non-Intrusive Assessment Philosophy

VulnScan Lite is engineered strictly for **defensive, passive reconnaissance and configuration auditing**:
- **Zero Exploitation**: Never sends SQL injection strings, XSS test vectors, command injection payloads, or active exploits.
- **Zero Fuzzing**: Never performs directory enumeration, parameter brute-forcing, or credential spraying.
- **Pure Passive Inspection**: Evaluates only standard HTTP response headers, SSL/TLS handshake parameters, and public HTML markup.
- **Non-Disruptive**: Guaranteed safe to run against production websites without triggering Denial of Service (DoS) conditions.

---

## 2. Multi-Tier SSRF Defense-in-Depth

The HTTP engine (`scanner/http.py`) enforces strict validation before initiating any outbound connection:
1. **Scheme Validation**: Whitelists `http://` and `https://` only. Rejects `file://`, `gopher://`, `dict://`, `ftp://`, etc.
2. **Pre-Request DNS Resolution**: Resolves target hostnames to all associated IP addresses before connecting.
3. **Comprehensive IP Blacklist**:
   - IPv4 Loopback (`127.0.0.0/8`, `localhost`)
   - IPv4 RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - IPv4 Link-Local & Cloud Metadata (`169.254.0.0/16`, `169.254.169.254`, `metadata.google.internal`)
   - IPv4 Broadcast & Reserved (`0.0.0.0/8`, `240.0.0.0/4`, `255.255.255.255/32`)
   - IPv6 Loopback (`::1`)
   - IPv6 Unique Local (`fc00::/7`)
   - IPv6 Link-Local (`fe80::/10`)
   - IPv4-Mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`)
   - Internal Domain Suffixes (`.local`, `.internal`, `.lan`, `.corp`, `.test`, `.invalid`, `.arpa`)
4. **Redirect Chain Re-Validation**: Re-evaluates destination URL against SSRF filters on **every redirect hop** (maximum 5 hops).

---

## 3. API Abuse Prevention & Hardening

1. **Atomic Redis Rate Limiting**:
   - Protects `POST /api/scans` from automated flooding.
   - Enforces a default limit of **10 scans per 60 seconds** per client IP.
   - Responds with `HTTP 429 Too Many Requests` and a standard `Retry-After` header.
   - Features a thread-safe sliding window fallback if Redis is temporarily unreachable.
2. **Payload Size Guardrails**:
   - Restricts incoming request bodies to **64 KB** (`MAX_REQUEST_BODY_BYTES = 65536`).
   - Rejects oversized requests with `HTTP 413 Payload Too Large`.
3. **Defensive Response Headers**:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
   - `Content-Security-Policy: default-src 'self'; ...`
4. **Information Leakage Prevention**:
   - Custom FastAPI and Celery error boundaries mask internal stack traces, DB connection strings, and Redis credentials.

---

## 4. Container & Infrastructure Security

1. **Non-Root Execution**:
   - Backend and Celery containers run as unprivileged user `vulnscan` (UID 1001 / GID 1001).
2. **Network Segmentation**:
   - Containers communicate over an isolated bridge network (`vulnscan_net`).
   - Redis port `6379` is internal to the Docker network and NOT exposed to the public host.
3. **Secret Isolation**:
   - `.dockerignore` excludes `.env`, `*.key`, `*.pem`, `credentials`, local database files, and caches from all container images.
4. **Volume Isolation**:
   - Database operations write to `/app/data` backed by the named Docker volume `vulnscan_sqlite_data`.

---

## 5. Production Deployment Security Checklist

Before deploying VulnScan Lite to production:
- [ ] Set `DEBUG=False` in environment configuration.
- [ ] Generate a secure, random 32-byte hexadecimal string for `SECRET_KEY`.
- [ ] Set `APP_ENV=production`.
- [ ] Deploy behind an HTTPS reverse proxy (e.g. Cloudflare, AWS ALB, Nginx TLS termination).
- [ ] Enable `ENABLE_HSTS=True` once real HTTPS is established.
- [ ] Restrict `CORS_ORIGINS` to trusted frontend domains only.
- [ ] Use PostgreSQL with strong credentials for production database persistence.
