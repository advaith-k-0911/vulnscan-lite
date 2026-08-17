# VulnScan Lite - Developer & Contribution Guide

---

## 1. Codebase Organization

VulnScan Lite maintains strict separation of concerns across four core packages:

```text
vulnscan-lite/
├── backend/                  # FastAPI Web Application & Celery Tasks
│   ├── app/
│   │   ├── main.py           # Application factory, middlewares, exception handlers
│   │   ├── config.py         # Pydantic Settings & environment variables
│   │   ├── database.py       # SQLAlchemy engine & session dependency
│   │   ├── models/           # SQLAlchemy ORM models (Scan)
│   │   ├── schemas/          # Pydantic validation & serialization schemas
│   │   ├── routes/           # FastAPI APIRouters (/scans, /health)
│   │   ├── services/         # ScanService persistence business logic
│   │   └── security/         # Rate limiting & security middlewares
│   ├── celery_app.py         # Celery instance configuration
│   └── tasks.py              # Asynchronous Celery worker task (run_scan)
├── scanner/                  # Passive Security Assessment Engine
│   ├── engine.py             # ScannerEngine orchestrator pipeline
│   ├── http.py               # HTTP client & multi-tier SSRF filter
│   ├── headers.py            # Security headers analyzer (zero I/O)
│   ├── tls.py                # TLS/SSL handshake & certificate auditor
│   ├── cms.py                # Passive CMS signature fingerprinter
│   ├── scoring.py            # 0-100 scoring & grade boundaries
│   └── remediation.py        # Multi-server remediation recipes (Nginx, Apache, Caddy)
├── reports/                  # PDF Report Generation Engine
│   └── pdf_generator.py      # ReportLab in-memory canvas & flowable compiler
├── frontend/                 # React SPA (Vite)
│   ├── src/
│   │   ├── components/       # Reusable UI components (Navbar, ScoreGauge, etc.)
│   │   ├── pages/            # Views (Scanner, Results, History, About, AboutApp)
│   │   ├── services/         # Centralized API client & error handling
│   │   └── tests/            # Vitest unit & component tests
│   └── nginx.conf            # Production Nginx reverse proxy configuration
└── tests/                    # Backend Pytest Test Suites (314 tests)
```

---

## 2. Development Guidelines

### Adding a New Scanner Check
1. **Module Placement**: Add new header checks in `scanner/headers.py`, TLS checks in `scanner/tls.py`, or CMS signatures in `scanner/cms.py`.
2. **Deterministic Output**: Every check must return a standardized `Finding` object (`id`, `name`, `category`, `status`, `severity`, `points`, `details`, `remediation`).
3. **Zero Active Attacks**: Never execute fuzzing, brute force, or payload injection.
4. **Remediation**: Add corresponding configuration snippets for Nginx, Apache, and Caddy in `scanner/remediation.py`.
5. **Testing**: Write dedicated deterministic unit tests in `tests/test_headers_scanner.py`, `tests/test_tls_scanner.py`, etc.

### Adding a New API Endpoint
1. **Route Definition**: Add the route in `backend/app/routes/scans.py` or create a new router in `backend/app/routes/`.
2. **Schema Validation**: Define Pydantic request/response models in `backend/app/schemas/scan.py`.
3. **Database Transactions**: Delegate database operations to `ScanService` in `backend/app/services/scan_service.py`.
4. **Error Handling**: Use standard `HTTPException` with structured status codes. Avoid raw exception leakage.
5. **Testing**: Add API unit and integration tests in `tests/test_api_scans.py` and `tests/test_async_scans.py`.

### Adding a Frontend Component
1. **Design System**: Use the Cyber Yellow (`#facc15`) + Pitch Black (`#000000`) theme tokens defined in `frontend/src/index.css`.
2. **Accessibility**: Ensure semantic HTML, descriptive `aria-label` attributes, and keyboard focus visibility.
3. **Testing**: Add component unit tests in `frontend/src/tests/frontend.test.jsx`.

---

## 3. Automated Testing Workflow

All contributions must pass the complete automated test suite before merging:

```bash
# 1. Run Complete Backend Test Suite (314 tests)
pytest tests/

# 2. Run Focused Backend Subsystems
pytest tests/test_http_scanner.py          # HTTP & SSRF core tests
pytest tests/test_security_hardening.py    # Security hardening & rate limit tests
pytest tests/test_scoring_boundaries.py    # Scoring & grade boundary tests
pytest tests/test_database_persistence.py  # Database models & pagination tests
pytest tests/test_celery_tasks.py          # Celery background execution tests
pytest tests/test_end_to_end_integration.py# Full pipeline integration tests
pytest tests/test_pdf_report.py            # PDF report compiler tests
pytest tests/test_docker_configuration.py  # Docker configuration tests

# 3. Run Frontend Test Suite (22 tests)
cd frontend
npm test

# 4. Verify Production Bundle Build
npm run build
```
