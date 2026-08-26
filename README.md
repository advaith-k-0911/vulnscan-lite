# VulnScan Lite

**Passive Web Vulnerability & Security Configuration Scanner**

Developed by: **Advaith K** (B.Tech CSE - Cyber Security)

---

## 1. Project Overview

**VulnScan Lite** is a lightweight, non-intrusive web security posture scanner engineered to identify common security misconfigurations and exposure risks across public web applications. 

Rather than executing invasive active attacks, fuzzers, or exploit payloads, VulnScan Lite employs **pure passive reconnaissance**. It audits publicly returned HTTP response headers, performs cryptographic TLS handshakes, measures response latency, inspects public HTML meta signatures, and computes a deterministic **0–100 Security Score** with letter grades (**A–F**) and actionable remediation guidance.

---

## 2. Mandatory Authorization Disclaimer

> **IMPORTANT**: Only scan websites you own or have explicit permission to assess.
>
> VulnScan Lite performs passive, non-intrusive security configuration analysis only and is **not** a replacement for a comprehensive penetration test or full security audit. Unauthorized vulnerability scanning against systems without prior written consent may violate applicable cybersecurity laws.

---

## 3. Key Implemented Features

- **Multi-Tier SSRF Defense**: Strict domain sanitization, pre-request DNS resolution, and IP filtering blocking private IPv4 ranges, loopbacks, link-local metadata (`169.254.169.254`), IPv6 loopback (`::1`), IPv6 unique local, and IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`).
- **Security Headers Audit**: Evaluates Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy with HTTPS-aware criteria.
- **TLS / SSL Health Analysis**: Validates certificate expiration dates, expiration calculation windows, TLS 1.2 / 1.3 protocol enforcement, and cipher suite cryptographic strength.
- **Passive CMS Detection**: Zero-traffic fingerprinting of popular content management systems (WordPress, Drupal, Joomla) via public meta tags, headers, and asset signatures.
- **Deterministic 0–100 Scoring & Grading**: Mathematical scoring algorithm with severity-weighted deductions (Critical: -25, High: -15, Medium: -10, Low: -5, Warning: -5), A–F letter grades, and anti-double-counting safeguards.
- **Actionable Multi-Server Remediation**: Technical rationale and copy-pasteable configuration recipes for **Nginx**, **Apache**, and **Caddy**.
- **Asynchronous Task Architecture**: Non-blocking `POST /api/scans` returns `HTTP 202 Accepted` immediately; Celery workers execute the scan in the background backed by Redis.
- **Persistent Database Storage**: Complete scan results, lifecycle states, scores, and timestamps stored in SQLite (local dev) / PostgreSQL (production) via SQLAlchemy 2.0.
- **Executive PDF Reporting**: On-demand, in-memory PDF generation and streaming using ReportLab with multi-page scaling and security health summaries.
- **Scan History**: Paginated scan history records from the persistent database with instant report navigation.
- **API Security Hardening**: Atomic Redis rate limiting (10 scans / 60s window with `HTTP 429 Too Many Requests`), request body size capping (64KB with `HTTP 413 Payload Too Large`), and defensive response headers.
- **Docker Compose Topology**: Production-ready 4-container stack (React Frontend via Nginx, FastAPI Backend, Celery Worker, Redis 7 Broker, and persistent named SQLite volume).
- **Cyber Yellow + Pitch Black UI**: High-contrast, clean cybersecurity aesthetic with accessible `:focus-visible` rings and `prefers-reduced-motion` compliance.

---

## 4. High-Level Architecture

```text
                    Browser (Client)
                           │
                           ▼
          React Frontend Container (Port 5173 / Nginx)
          ├── Serves compiled Vite SPA bundle (Cyber Yellow + Pitch Black)
          ├── Static assets caching (1y) & gzip compression
          └── Reverse proxies /api/ and /health to backend
                           │ (Internal Docker Network)
                           ▼
          FastAPI REST Backend Container (Port 8000 / Uvicorn)
          ├── Rate limiting, payload size cap, security headers
          ├── Multi-tier SSRF defense & input validation
          ├── Asynchronous scan creation (202 Accepted)
          └── In-memory ReportLab PDF compilation
             ┌─────────────┴─────────────┐
             ▼                           ▼
      Database Storage             Redis Container (Port 6379)
      (Named Volume)               (Celery Broker & Rate Limiter)
      /app/data/vulnscan.db                      │
                                                 ▼
                                   Celery Worker Container
                                   (Runs Scanner Engine)
                                                 │
                                                 ▼
                                     Target Host (Internet)
                                     (Passive Audit Only)
```

---

## 5. Technology Stack

| Layer | Technologies | Role / Specifications |
| :--- | :--- | :--- |
| **Frontend** | React 18, Vite 6, Vanilla CSS | Single Page Application (SPA), accessible UI, responsive layout |
| **Backend API** | Python 3.11+, FastAPI, Uvicorn, Pydantic v2 | High-performance asynchronous REST API |
| **Task Queue** | Celery 5.4, Redis 7 (Alpine) | Distributed asynchronous background worker and message broker |
| **Database** | SQLAlchemy 2.0, SQLite / PostgreSQL | Authoritative persistent data source for scans and reports |
| **Reporting** | ReportLab 4.0+ | In-memory binary PDF document compiler and streaming engine |
| **Testing** | Pytest 8.4+, Vitest 3.2+ | Automated unit, integration, security, and component testing |
| **Containerization** | Docker, Docker Compose v2 | Multi-container isolated execution and volume persistence |

---

## 6. Project Structure & Documentation Set

```text
vulnscan-lite/
├── backend/                  # FastAPI Application & Celery Worker
├── scanner/                  # Passive Security Assessment Engine
├── reports/                  # PDF Report Generation Engine
├── frontend/                 # React SPA (Vite)
├── tests/                    # Backend Pytest Test Suites (314 tests)
├── docker-compose.yml        # 4-container production topology
├── .env.example              # Environment variables template
├── .env.production.example   # Production environment template
├── ARCHITECTURE.md           # Deep architectural specification & lifecycle
├── API.md                    # Complete REST API reference
├── SCANNER.md                # Comprehensive scanner engine documentation
├── SECURITY.md               # Security hardening & guardrails guide
├── SETUP.md                  # Developer setup & operations guide
├── DEVELOPMENT.md            # Contributor & developer workflow guide
├── DEPLOYMENT.md             # Production deployment & operations guide
├── FINAL_AUDIT_REPORT.md     # 20-section final audit report
├── DEPLOYMENT_REPORT.md      # 23-section live deployment report
├── PROJECT_STATUS.md         # Single source of truth for project state
└── README.md                 # Primary project overview
```

---

## 7. Quick Start (Running with Docker)

```bash
# 1. Build and start all services in the background
docker compose up --build -d

# 2. Verify all services are healthy and running
docker compose ps

# 3. Access the application:
#    Frontend UI:  http://localhost:5173
#    Swagger Docs: http://localhost:8000/docs
#    Health Probe: http://localhost:5173/health

# 4. View live logs
docker compose logs -f

# 5. Stop the application
docker compose down
```

---

## 8. Local Non-Docker Development

```bash
# 1. Install backend dependencies
pip install -r backend/requirements.txt

# 2. Start Redis broker
docker run -d -p 6379:6379 --name vulnscan-redis redis:7-alpine

# 3. Start Celery worker
celery -A backend.celery_app.celery_app worker --loglevel=info

# 4. Start FastAPI server (in a separate terminal)
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# 5. Start React frontend (in a separate terminal)
cd frontend
npm install
npm run dev
```

---

## 9. Automated Testing & Verification

```bash
# 1. Backend test suite (314 tests)
pytest tests/

# 2. Frontend test suite (22 tests)
cd frontend
npm test

# 3. Production bundle compilation
npm run build
```

---

## 10. Production Deployment

VulnScan Lite includes a **Render Blueprint** (`render.yaml`) for a free-tier deployment with managed PostgreSQL, a FastAPI web service, and a React static site. Scans run through FastAPI background tasks in this setup. Docker Compose deployments use Redis and a Celery worker for queued scan processing.

For step-by-step instructions, environment variables configuration, and VPS Docker Compose guides, refer to [`DEPLOYMENT.md`](./DEPLOYMENT.md) and [`render.yaml`](./render.yaml).

---

## 11. Developer Attribution

Developed by: **Advaith K**
- **Education**: B.Tech in Computer Science & Engineering (Specialization in Cyber Security)
- **Role**: Project Architect & Security Engineer
- **Profiles**: [LinkedIn](https://www.linkedin.com/in/advaith-k-21jul2006) • [GitHub](https://github.com/advaith-k-0911/vulnscan-lite)

---

## 12. License

This project is open source and available under the terms of the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See the [`LICENSE`](./LICENSE) file for the full license text.
