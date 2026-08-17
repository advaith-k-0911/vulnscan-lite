# VulnScan Lite - System Architecture & Execution Lifecycle

---

## 1. High-Level Architecture Overview

VulnScan Lite is an asynchronous, multi-tiered passive web vulnerability and security configuration assessment platform.

```text
                    Browser (User Client)
                              │
                              ▼
          Frontend Container (Nginx Alpine • Port 5173 / 80)
          ├── React 18 SPA (Vite Production Bundle)
          ├── SPA Client-Side Routing (try_files /index.html)
          ├── Security Response Headers (nosniff, DENY, referrer)
          └── Reverse Proxy Engine (/api/ & /health -> backend:8000)
                              │
                              ▼ (vulnscan_net Bridge Network)
          Backend API Container (Python 3.11 Slim • Port 8000)
          ├── FastAPI REST Service (Uvicorn)
          ├── Request Body Limiter (64KB payload bounds)
          ├── Rate Limiting Middleware (Atomic Redis Token/Sliding Window)
          ├── Security Response Headers Middleware
          ├── Unified Error Boundary (Leakage-free exception masking)
          └── In-Memory ReportLab PDF Generator (Binary streaming)
              ┌───────────────┴───────────────┐
              ▼                               ▼
      Persistent Database              Redis Service Container
      (Named Volume: sqlite_data)      (Redis 7 Alpine • Port 6379)
      /app/data/vulnscan.db            ├── Celery Task Broker
      (SQLAlchemy 2.0 ORM)             └── Rate Limiter Counter Store
                                                      │
                                                      ▼
                                       Celery Worker Container
                                       (Python 3.11 Slim)
                                       ├── Asynchronous task execution
                                       ├── DB status synchronization
                                       └── Passive Scanner Core Engine
                                                      │
                                                      ▼
                                           Target Host (Internet)
                                           (Non-Intrusive Assessment)
```

---

## 2. Multi-Container Docker Topology

| Service Name | Base Image | Ports | Role | Health Check |
| :--- | :--- | :--- | :--- | :--- |
| **`redis`** | `redis:7-alpine` | `6379` (internal) | Task broker & rate limit counter store | `redis-cli ping` |
| **`backend`** | `python:3.11-slim` | `8000:8000` | FastAPI REST API, ReportLab PDF compiler | `python -c urllib /health` |
| **`celery_worker`** | `python:3.11-slim` | None (internal) | Executes passive scans asynchronously | Dependent on Redis & Backend |
| **`frontend`** | `nginx:alpine` (multi-stage) | `5173:80` | Serves React SPA & reverse proxies `/api/` | Dependent on Backend |

---

## 3. Detailed Scan Request & Execution Lifecycle

The end-to-end flow from target submission to final PDF generation:

1. **Target Submission**: User enters target URL in the React frontend and clicks "Start Scan".
2. **Frontend Validation**: Client-side regex checks syntax and prevents empty submissions.
3. **API Request**: Frontend issues `POST /api/scans` with payload `{"target_url": "https://example.com"}`.
4. **FastAPI Guardrails**: Rate limiter checks token bucket (10 req / 60s); body size limiter ensures payload < 64KB.
5. **SSRF Pre-Validation**: Backend normalizes URL, resolves DNS, and validates IP against blacklists.
6. **Database Record Initialized**: `ScanService` inserts a new `Scan` row with a unique UUID4 in `QUEUED` state.
7. **Task Enqueued**: FastAPI dispatches `run_scan.delay(scan_id)` to Celery and immediately returns `HTTP 202 Accepted`.
8. **Frontend Polling Initiated**: Frontend switches to `ScanProgress` view and polls `GET /api/scans/{id}/status` every 2 seconds.
9. **Worker Pick-Up**: Celery worker dequeues the task and updates database status to `RUNNING`.
10. **Scanner Orchestration**:
    - **HTTP Engine**: Performs safe GET request, checks redirects, captures headers and latency.
    - **Security Headers Engine**: Evaluates CSP, HSTS, XFO, XCTO, Referrer, Permissions-Policy (zero network I/O).
    - **TLS Engine**: Performs standard SSL socket handshake to inspect certificate validity, TLS version, and ciphers.
    - **CMS Fingerprinter**: Evaluates public meta tags and asset paths for WordPress, Drupal, Joomla signatures.
11. **Scoring & Remediation**: Scoring engine computes 0–100 score and letter grade (A–F); remediation engine attaches fix guidance.
12. **Database Result Persisted**: Worker writes full JSON report, score, and grade to the database row and marks status `COMPLETED`.
13. **Dashboard Transition**: Frontend status poll receives `COMPLETED` and redirects to `/results/{scan_id}`.
14. **Dashboard Render**: Results page renders `ScoreGauge`, posture overview cards, category filters, and finding drawers.
15. **On-Demand PDF Generation**: Clicking "Download PDF" calls `GET /api/scans/{id}/report/pdf`; backend compiles the PDF in memory via ReportLab and streams the binary to the browser.

---

## 4. Data Persistence & Volume Management

- **Named Volume**: `vulnscan_sqlite_data` is mounted at `/app/data` inside both `backend` and `celery_worker` containers.
- **Database File**: `/app/data/vulnscan.db`.
- **Integrity**: Survives container restarts, rebuilds, and standard `docker compose down` cycles.
- **Production PostgreSQL Support**: Switching to PostgreSQL only requires setting `DATABASE_URL=postgresql://user:pass@host:5432/dbname`.
