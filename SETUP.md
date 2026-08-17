# VulnScan Lite - Setup & Developer Guide

## 1. Prerequisites

### For Docker Deployment (Recommended):
- **Docker**: Engine 20.10+
- **Docker Compose**: v2.0+

### For Local Non-Docker Development:
- **Python**: 3.11 or newer (Python 3.13 tested)
- **Node.js**: v18 or newer (Node v24 tested)
- **Redis**: v7.0 or newer
- **Git**

---

## 2. Running with Docker Compose (Recommended)

### Start the Application:
```bash
# Clone the repository and navigate into the root directory
cd vulnscan-lite

# Build and start all 4 services (Redis, Backend, Celery Worker, Frontend)
docker compose up --build -d
```

### Access Services:
- **Frontend Dashboard**: `http://localhost:5173`
- **FastAPI Documentation (Swagger UI)**: `http://localhost:8000/docs`
- **Application Health Probe**: `http://localhost:5173/health`

### Common Docker Commands:
```bash
# View live tail of container logs
docker compose logs -f

# Inspect specific service logs
docker compose logs -f backend
docker compose logs -f celery_worker
docker compose logs -f redis
docker compose logs -f frontend

# Restart a specific service
docker compose restart backend

# Execute a shell inside the backend container
docker compose exec backend bash

# Run pytest inside the backend container
docker compose exec backend pytest tests/

# Gracefully stop the application
docker compose down

# Stop and wipe persistent SQLite volume (clean start)
docker compose down -v
```

---

## 3. Local Non-Docker Development Workflow

### Step 1: Environment Configuration
Create `.env` in the project root:
```bash
cp .env.example .env
```

### Step 2: Install Dependencies
```bash
# Python backend dependencies
pip install -r backend/requirements.txt

# Node frontend dependencies
cd frontend
npm install
cd ..
```

### Step 3: Start Redis Broker
```bash
# Run Redis via Docker container
docker run -d -p 6379:6379 --name vulnscan-redis redis:7-alpine

# Or start local Redis daemon on Linux/macOS
# redis-server
```

### Step 4: Start Celery Worker
```bash
# Windows
celery -A backend.celery_app.celery_app worker --loglevel=info --pool=solo

# Linux / macOS
celery -A backend.celery_app.celery_app worker --loglevel=info
```

### Step 5: Start FastAPI Backend
```bash
# Start Uvicorn development server on port 8000
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 6: Start React Frontend
```bash
cd frontend
npm run dev
```

---

## 4. Production Deployment

For complete live deployment instructions using Docker VPS, Render, Railway, AWS ECS, or Fly.io with managed PostgreSQL and Let's Encrypt TLS termination, refer to [`DEPLOYMENT.md`](./DEPLOYMENT.md) and [`DEPLOYMENT_REPORT.md`](./DEPLOYMENT_REPORT.md).

---

## 5. Running Automated Tests

```bash
# 1. Complete Backend & Docker Configuration Test Suite (314 tests)
pytest tests/

# 2. Focused Subsystem Runs
pytest tests/test_docker_configuration.py  # Dockerfile & Compose topology tests
pytest tests/test_http_scanner.py          # HTTP & SSRF core tests
pytest tests/test_security_hardening.py    # Security hardening & rate limit tests
pytest tests/test_scoring_boundaries.py    # Scoring & grade boundary tests
pytest tests/test_database_persistence.py  # Database models & pagination tests
pytest tests/test_celery_tasks.py          # Celery background execution tests
pytest tests/test_end_to_end_integration.py# Full pipeline integration tests
pytest tests/test_pdf_report.py            # PDF report compiler tests

# 3. Frontend Unit & UI Tests (22 tests)
cd frontend
npm test

# 4. Production Bundle Build Verification
npm run build
```

---

## 6. Environment Variables Reference

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `APP_NAME` | `VulnScan Lite` | Name of the application |
| `APP_ENV` | `development` | Environment mode (`development`, `testing`, `production`) |
| `DEBUG` | `False` | Debug mode (must be `False` in production) |
| `HOST` | `127.0.0.1` | Host interface for FastAPI binding |
| `PORT` | `8000` | Port for FastAPI binding |
| `SECRET_KEY` | `default-development-...` | Cryptographic signing key (rotate in production) |
| `DATABASE_URL` | `sqlite:///./vulnscan.db` | SQLAlchemy database connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis counter store for atomic rate limiting |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery task queue broker connection string |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Celery task result backend connection string |
| `SCANNER_TIMEOUT_SECONDS` | `10` | Maximum timeout for HTTP/TLS connections |
| `SCANNER_MAX_REDIRECTS` | `5` | Maximum redirect hops allowed |
| `SCANNER_MAX_RESPONSE_BYTES` | `5242880` (5MB) | Maximum HTTP response body size limit |
| `RATE_LIMIT_ENABLED` | `True` | Enables atomic API rate limiting |
| `RATE_LIMIT_SCAN_CREATION_LIMIT` | `10` | Max scans allowed per client IP per window |
| `RATE_LIMIT_SCAN_CREATION_WINDOW` | `60` | Rate limiting window size in seconds |
| `MAX_REQUEST_BODY_BYTES` | `65536` (64KB) | Maximum allowed API request payload size |
| `ENABLE_HSTS` | `False` | Enables HSTS header (enable only over real HTTPS) |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Allowed CORS origins for browser access |

---

## 7. Docker Troubleshooting Matrix

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| **Port 5173 or 8000 in use** | Another local process is listening on the port | Stop conflicting process or modify host port in `docker-compose.yml` (e.g. `"8080:80"`). |
| **Redis connection refused** | Redis container not healthy yet | `docker-compose.yml` uses `condition: service_healthy` on Redis. Ensure Redis container is running: `docker compose ps`. |
| **Celery worker cannot reach Redis** | Incorrect hostname in worker configuration | Worker must use `REDIS_URL=redis://redis:6379/0` (not `localhost`) inside Docker network. |
| **Database changes lost after restart** | Ephemeral container storage | SQLite database is mounted to named volume `sqlite_data:/app/data`. Do not run `docker compose down -v` if you want data persisted. |
| **Frontend cannot reach backend API** | CORS or DNS resolution mismatch | Frontend Nginx container reverse proxies `/api/` directly to `http://backend:8000/api/`, eliminating client CORS errors. |
| **Stale build cache** | Docker cached old layer | Rebuild without cache: `docker compose build --no-cache`. |
