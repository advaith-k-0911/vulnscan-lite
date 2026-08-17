"""
VulnScan Lite - Phase 18 Dockerization & Docker Compose Test Suite
Validates Dockerfiles, Nginx reverse proxy configuration, Docker Compose service topology,
healthchecks, network segmentation, persistent storage volumes, and non-root execution.
"""

from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestDockerComposeTopology:
    """Validate docker-compose.yml configuration and service definitions."""

    @pytest.fixture(autouse=True)
    def load_compose_content(self):
        compose_path = PROJECT_ROOT / "docker-compose.yml"
        assert compose_path.exists(), "docker-compose.yml must exist in project root"
        self.content = compose_path.read_text(encoding="utf-8")

    def test_compose_file_version_and_structure(self):
        assert "version: '3.8'" in self.content or 'version: "3.8"' in self.content
        assert "services:" in self.content
        assert "volumes:" in self.content
        assert "networks:" in self.content

    def test_redis_service_configuration(self):
        assert "redis:" in self.content
        assert "image: redis:7-alpine" in self.content
        assert "vulnscan_redis" in self.content
        assert "redis-cli" in self.content  # Healthcheck ping
        assert "vulnscan_net" in self.content

    def test_backend_service_configuration(self):
        assert "backend:" in self.content
        assert "dockerfile: backend/Dockerfile" in self.content
        assert "vulnscan_backend" in self.content
        assert '"8000:8000"' in self.content
        assert "REDIS_URL=redis://redis:6379/0" in self.content
        assert "CELERY_BROKER_URL=redis://redis:6379/0" in self.content
        assert "DATABASE_URL=sqlite:////app/data/vulnscan.db" in self.content
        assert "sqlite_data:/app/data" in self.content
        assert "service_healthy" in self.content
        assert "vulnscan_net" in self.content

    def test_celery_worker_service_configuration(self):
        assert "celery_worker:" in self.content
        assert "vulnscan_celery_worker" in self.content
        assert "backend.celery_app" in self.content
        assert "REDIS_URL=redis://redis:6379/0" in self.content
        assert "DATABASE_URL=sqlite:////app/data/vulnscan.db" in self.content
        assert "sqlite_data:/app/data" in self.content
        assert "vulnscan_net" in self.content

    def test_frontend_service_configuration(self):
        assert "frontend:" in self.content
        assert "vulnscan_frontend" in self.content
        assert '"5173:80"' in self.content
        assert "vulnscan_net" in self.content

    def test_persistent_volumes_and_networks(self):
        assert "sqlite_data:" in self.content
        assert "vulnscan_sqlite_data" in self.content
        assert "vulnscan_net:" in self.content
        assert "vulnscan_network" in self.content


class TestBackendDockerfile:
    """Validate backend/Dockerfile security and execution settings."""

    @pytest.fixture(autouse=True)
    def load_dockerfile(self):
        dockerfile_path = PROJECT_ROOT / "backend" / "Dockerfile"
        assert dockerfile_path.exists(), "backend/Dockerfile must exist"
        self.content = dockerfile_path.read_text(encoding="utf-8")

    def test_base_image(self):
        assert "FROM python:3.11-slim" in self.content

    def test_non_root_user_creation(self):
        assert "useradd" in self.content
        assert "vulnscan" in self.content
        assert "USER vulnscan" in self.content

    def test_data_directory_for_sqlite_persistence(self):
        assert "mkdir -p /app/data" in self.content
        assert "chown" in self.content

    def test_dependency_installation_no_cache(self):
        assert "pip install --no-cache-dir -r /app/backend/requirements.txt" in self.content

    def test_port_exposure_and_entrypoint(self):
        assert "EXPOSE 8000" in self.content
        assert "uvicorn" in self.content
        assert "backend.app.main:app" in self.content


class TestFrontendDockerfileAndNginx:
    """Validate frontend multi-stage build and Nginx reverse proxy configuration."""

    def test_frontend_dockerfile_multi_stage(self):
        dockerfile_path = PROJECT_ROOT / "frontend" / "Dockerfile"
        assert dockerfile_path.exists()
        content = dockerfile_path.read_text(encoding="utf-8")

        assert "FROM node:20-alpine AS builder" in content
        assert "npm ci" in content
        assert "npm run build" in content
        assert "FROM nginx:alpine" in content
        assert "COPY --from=builder /app/dist /usr/share/nginx/html" in content
        assert "COPY nginx.conf /etc/nginx/conf.d/default.conf" in content
        assert "EXPOSE 80" in content

    def test_frontend_nginx_configuration(self):
        nginx_path = PROJECT_ROOT / "frontend" / "nginx.conf"
        assert nginx_path.exists()
        content = nginx_path.read_text(encoding="utf-8")

        # SPA Routing
        assert "try_files $uri $uri/ /index.html;" in content

        # API Reverse Proxy to Backend
        assert "location /api/ {" in content
        assert "proxy_pass http://backend:8000/api/;" in content

        # Health Probe Proxy
        assert "location /health {" in content
        assert "proxy_pass http://backend:8000/health;" in content

        # Security Headers
        assert 'add_header X-Content-Type-Options "nosniff"' in content
        assert 'add_header X-Frame-Options "DENY"' in content
        assert 'add_header Referrer-Policy "strict-origin-when-cross-origin"' in content


class TestDockerIgnoreSecurity:
    """Validate .dockerignore exclusions preventing secret leaks."""

    def test_root_dockerignore_exclusions(self):
        ignore_path = PROJECT_ROOT / ".dockerignore"
        assert ignore_path.exists()
        content = ignore_path.read_text(encoding="utf-8")

        assert ".env" in content
        assert ".git" in content
        assert "__pycache__" in content
        assert "node_modules" in content
        assert "*.db" in content
        assert "*.sqlite" in content

    def test_frontend_dockerignore_exclusions(self):
        ignore_path = PROJECT_ROOT / "frontend" / ".dockerignore"
        assert ignore_path.exists()
        content = ignore_path.read_text(encoding="utf-8")

        assert "node_modules" in content
        assert "dist" in content
        assert ".env" in content
