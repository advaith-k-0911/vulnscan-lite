# VulnScan Lite - AI Context & Master Specification

## 1. Project Identity & Overview
- **Project Name**: VulnScan Lite
- **Project Type**: Passive Web Vulnerability & Security Configuration Scanner
- **Developer**: Advaith K
- **Education/Background**: B.Tech CSE (Cyber Security) Student
- **Project Purpose**: Provide authorized users with a comprehensive, professional security health assessment of websites via passive, non-intrusive analysis.

---

## 2. Core User Flow & Architecture
```text
User 
  ↓ (Enter URL)
URL Validation & SSRF Guard
  ↓
Create Scan Record (Status: QUEUED)
  ↓
Redis Queue / Celery Worker
  ↓
Scanner Engine (Controlled Passive Analysis)
  ├── HTTP/HTTPS Analysis
  ├── Security Header Analysis
  ├── TLS/SSL Certificate & Cipher Inspection
  └── Passive CMS Indicator Detection
  ↓
Scoring & Grading (0-100 deterministic scale, A-F)
  ↓
Remediation Generator
  ↓
Database Persistence (SQLite initially, PostgreSQL ready)
  ↓
Results Dashboard (Polling ~2s during execution)
  ↓
PDF Security Health Report (ReportLab)
```

---

## 3. Passive Scanning Safety Boundaries
**VulnScan Lite is strictly a passive analysis and security posture tool.**

### Permitted Operations:
- Controlled HTTP and HTTPS requests with reasonable timeouts, redirect limits, and response-size caps.
- Inspection of HTTP response headers.
- Parsing and analysis of returned public HTML structure.
- Inspection of TLS/SSL certificates, expiration, cipher suites, and protocol versions via Python's standard `ssl` module.
- Passive CMS identification via public HTML generator tags, response headers, and known resource paths.
- Generation of deterministic configuration ratings and tailored remediation advice.

### Strictly Forbidden Operations:
- Exploitation or vulnerability weaponization.
- Brute forcing or dictionary attacks (directories, passwords, tokens).
- Fuzzing or SQL/XSS/Command payload injection.
- Authentication bypass or credential stuffing.
- Aggressive web crawling or scraping.
- Automated attack chaining.

### Mandatory Disclaimer:
> **"Only scan websites you own or have permission to assess. This tool performs passive analysis only."**
> Must be clearly displayed in the user interface and generated PDF reports.

---

## 4. Technology Stack
- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, Pydantic
- **Scanner Core**: Python (`httpx`/`requests`, `BeautifulSoup4`, `ssl`, `socket`, `ipaddress`)
- **Task Queue**: Celery with Redis broker
- **Database**: SQLite (initial/development) with architecture ready for PostgreSQL migration
- **Frontend**: React (Vite, clean Vanilla CSS design system, responsive, high visual quality)
- **PDF Generation**: ReportLab
- **Containerization**: Docker & Docker Compose
- **Version Control**: Git & GitHub

---

## 5. Scanner Modules & Logic
- `scanner/http.py`: Availability, response time, HTTP status, final URL, redirect chain, content-type.
- `scanner/headers.py`: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- `scanner/tls.py`: Certificate validity, expiration date, issuer/subject, hostname verification, TLS version, cipher strength.
- `scanner/cms.py`: Passive CMS detection (WordPress, Drupal, Joomla) without version vulnerability assumptions.
- `scanner/scoring.py`: Centralized 0–100 deterministic scoring engine (90–100: A, 80–89: B, 70–79: C, 60–69: D, 0–59: F).
- `scanner/remediation.py`: Actionable remediation guidance with non-prescriptive, cross-platform configuration examples.
- `scanner/engine.py`: Orchestrator combining all passive inspection modules into a unified report.

---

## 6. Security of VulnScan Lite (Self-Defense)
- **SSRF Protection**: Strict IP resolution and validation blocking `localhost`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254` (cloud metadata), and IPv6 loopback/link-local addresses.
- **Request Guardrails**: Request timeouts (max 10s), max redirects (max 5), max response size caps (max 5MB).
- **Authentication & Multi-Tenancy**: Isolated scan histories per user with secure password hashing (Argon2 / bcrypt) and JWT authorization.
- **Input Sanitization**: Strict URL schema validation (`http`, `https` only) and domain format checks.

---

## 7. UI & Design Direction
- **Style**: Professional, dark/neutral cybersecurity aesthetic, focused on data density, clean typography, balanced spacing, and subtle border accents.
- **Avoid**: Neon hacker tropes, terminal gimmicks, fake statistics, pulsing biscuit pills, decorative gradients, and cluttered cards.
- **Pages**:
  1. `Scanner`: Clean URL input, safety disclaimer, initiate scan.
  2. `Scan Progress`: Polling status indicator with live step updates.
  3. `Results Dashboard`: Score card, grade badge, executive summary, passed/failed/warning checks, remediation guides, PDF download.
  4. `Scan History`: Previous scans, target, score, grade, timestamp, comparison trends.
  5. `About Developer`: Minimalist profile for **Advaith K**, B.Tech CSE (Cyber Security) Student with real GitHub & LinkedIn links. No photos, fake bios, or skill bars.

---

## 8. AI Handoff & Continuity Rules
1. **Single Source of Truth**: `PROJECT_STATUS.md` tracks real-time progress, exact current state, and the next step.
2. **Historical Log**: `DEVELOPMENT_LOG.md` tracks chronological changes, tests, and milestone summaries.
3. **Phase-by-Phase Execution**: Never jump ahead to future phases. Only implement the explicitly requested phase.
4. **Verification Requirement**: Never mark any task or phase as complete until all corresponding code and tests have been executed and verified.
