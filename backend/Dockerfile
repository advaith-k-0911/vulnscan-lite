# VulnScan Lite - Backend & Worker Dockerfile
# Python 3.11 Slim image with non-root security execution

FROM python:3.11-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Create non-root system user and data directory for SQLite persistence
RUN groupadd -g 1001 vulnscan && \
    useradd -u 1001 -g vulnscan -s /bin/bash -m vulnscan && \
    mkdir -p /app/data && \
    chown -R vulnscan:vulnscan /app

# Install dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend, scanner, and report modules
COPY --chown=vulnscan:vulnscan backend /app/backend
COPY --chown=vulnscan:vulnscan scanner /app/scanner
COPY --chown=vulnscan:vulnscan reports /app/reports

# Run as non-root user
USER vulnscan

# Expose internal API port
EXPOSE 8000

# Default command starts the FastAPI Uvicorn server
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
