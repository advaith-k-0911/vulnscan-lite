# VulnScan Lite - Production Deployment & Live Operations Guide

**Developer / Maintainer**: **Advaith K** (B.Tech CSE - Cyber Security)  
**Version**: `v1.0.0` (Production Ready)  
**Target Provider**: **Render (Managed Cloud Infrastructure)**  

---

## 1. Production Architecture on Render

VulnScan Lite is structured to deploy seamlessly using the included **Render Blueprint** (`render.yaml`):

```text
                                INTERNET
                                   │
                                   ▼
                      [ Render Edge / HTTPS ]
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
        [ React Frontend Static Site ]  [ FastAPI Web Service ]
        (vulnscan-frontend.onrender.com) (vulnscan-backend.onrender.com)
                    │                             │
                    └──────────────┬──────────────┘
                                   │ (Render Private Network)
             ┌─────────────────────┼─────────────────────┐
             ▼                     ▼                     ▼
   [ Managed PostgreSQL ]   [ Managed Redis ]    [ Celery Worker ]
       (vulnscan-db)        (vulnscan-redis)     (vulnscan-worker)
                                                         │
                                                         ▼
                                                [ Target Website ]
                                                (Public Internet)
```

---

## 2. Step-by-Step Render Deployment Guide

### Step 1: Push Repository to GitHub
1. Create a repository on GitHub (e.g. `your-username/vulnscan-lite`).
2. Push the complete project code:
   ```bash
   git init
   git add .
   git commit -m "feat: complete VulnScan Lite application ready for Render"
   git branch -M main
   git remote add origin https://github.com/your-username/vulnscan-lite.git
   git push -u origin main
   ```

---

### Step 2: Deploy via Render Blueprint (`render.yaml`)
1. Log in to your [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** in the top navigation and select **Blueprint**.
3. Connect your GitHub account and select your `vulnscan-lite` repository.
4. Render will automatically discover `render.yaml` and display the 5 resources:
   - `vulnscan-db` (PostgreSQL Database)
   - `vulnscan-redis` (Redis Key-Value Service)
   - `vulnscan-backend` (FastAPI Web Service)
   - `vulnscan-worker` (Celery Background Worker)
   - `vulnscan-frontend` (Static Site)
5. Click **Apply** to trigger automated infrastructure provisioning.

---

### Step 3: Configure Service URLs & Cross-Origin Settings
Once the services are created:
1. **Connect Frontend to Backend**:
   - Copy the backend URL (e.g. `https://vulnscan-backend.onrender.com`).
   - Go to `vulnscan-frontend` -> **Environment** -> set `VITE_API_BASE_URL` = `https://vulnscan-backend.onrender.com`.
   - Click **Save Changes** (Render will trigger a quick frontend re-build).
2. **Whitelist Frontend in Backend CORS**:
   - Copy the frontend URL (e.g. `https://vulnscan-frontend.onrender.com`).
   - Go to `vulnscan-backend` -> **Environment** -> set `CORS_ORIGINS` = `https://vulnscan-frontend.onrender.com`.
   - Click **Save Changes** (Render will automatically reload the backend).

---

### Step 4: Verify Live Application & Perform First Scan
1. **Verify Backend Health**:
   - Open `https://vulnscan-backend.onrender.com/health` in your browser.
   - Expected response: `{"status": "healthy", "app": "VulnScan Lite"}`.
2. **Launch Frontend Dashboard**:
   - Open `https://vulnscan-frontend.onrender.com`.
3. **Execute Live Verification Scan**:
   - Enter `https://example.com` into the URL input and click **Start Scan**.
   - Verify that the scan enters `QUEUED`, transitions to `RUNNING` as `vulnscan-worker` picks it up, and completes with a full findings report and 0–100 score.
   - Verify that clicking **Download PDF** generates the executive report.
   - Verify that the scan appears in **Scan History**.

---

## 3. Alternative: Single-Host Docker Compose Deployment (Cloud VPS)

If hosting on an Ubuntu VPS (AWS EC2, DigitalOcean, Linode, Hetzner):

```bash
# 1. Clone repository
git clone https://github.com/your-username/vulnscan-lite.git /opt/vulnscan-lite
cd /opt/vulnscan-lite

# 2. Configure production environment
cp .env.production.example .env
nano .env

# 3. Launch full stack via Docker Compose
docker compose up --build -d

# 4. Check service status
docker compose ps
```

---

## 4. Production Security Checklist

- [x] **DEBUG=False**: Debug mode disabled in production.
- [x] **Strong SECRET_KEY**: Generated via `python -c "import secrets; print(secrets.token_hex(32))"`.
- [x] **Private Infrastructure**: Redis and PostgreSQL are private to the internal network.
- [x] **Multi-Tier SSRF Filter**: Blocks private IPv4/IPv6, loopbacks, link-local metadata (`169.254.169.254`), and IPv4-mapped IPv6 ranges.
- [x] **Rate Limiting**: Enforced at 10 scans / 60s per client IP (`HTTP 429 Too Many Requests`).
- [x] **Payload Bounds**: Enforced at 64KB (`HTTP 413 Payload Too Large`).
- [x] **Defensive Headers**: `nosniff`, `DENY`, `strict-origin-when-cross-origin`, `Permissions-Policy` applied.

---

## 5. Live Monitoring & Troubleshooting

### Viewing Logs in Render:
- **Backend API Logs**: Go to `vulnscan-backend` -> **Logs** (monitor incoming requests and health probes).
- **Worker Logs**: Go to `vulnscan-worker` -> **Logs** (monitor active scan jobs and completed tasks).

### Troubleshooting Matrix:
| Symptom | Root Cause | Resolution |
| :--- | :--- | :--- |
| **Frontend shows Network Error** | `VITE_API_BASE_URL` missing or CORS error | Ensure `VITE_API_BASE_URL` in `vulnscan-frontend` points to backend URL, and `CORS_ORIGINS` in `vulnscan-backend` contains the frontend URL. |
| **Scan stays in QUEUED indefinitely** | Celery worker not connected to Redis | Check `vulnscan-worker` logs. Verify `REDIS_URL` / `CELERY_BROKER_URL` matches `vulnscan-redis` connection string. |
| **Database connection error** | PostgreSQL service sleeping or building | Verify `vulnscan-db` is marked available and `DATABASE_URL` is populated. |

---

## 6. Rollback & Disaster Recovery

### Render Rollback:
1. In the Render dashboard, navigate to the affected service (`vulnscan-backend` or `vulnscan-frontend`).
2. Click **Events** / **Deploys**.
3. Locate the previous working deploy and click **Rollback to this deploy**.
