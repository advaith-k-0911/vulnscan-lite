# VulnScan Lite - REST API Specification & Endpoint Reference

## 1. Overview
The VulnScan Lite REST API provides asynchronous scanning, real-time lifecycle tracking, deep vulnerability report retrieval, paginated history queries, and in-memory ReportLab PDF compilation.

**Base URLs**:
- **Local FastAPI**: `http://localhost:8000`
- **Dockerized Frontend Reverse Proxy**: `http://localhost:5173/api`
- **Interactive OpenAPI Documentation**: `http://localhost:8000/docs`

---

## 2. API Endpoints

### 1. `GET /health`
Liveness and readiness probe for health monitoring and container readiness.

- **Method**: `GET`
- **Path**: `/health`
- **Authentication**: None
- **Rate Limit**: Exempt
- **Status Codes**:
  - `200 OK`: Server is operational and healthy.
- **Example cURL**:
  ```bash
  curl -s http://localhost:8000/health
  ```
- **Example Response (200 OK)**:
  ```json
  {
    "status": "healthy",
    "app": "VulnScan Lite",
    "timestamp": "2026-08-17T14:00:00Z"
  }
  ```

---

### 2. `POST /api/scans`
Submits a target website URL for asynchronous passive security assessment.

- **Method**: `POST`
- **Path**: `/api/scans`
- **Rate Limit**: 10 requests per 60-second window (per client IP)
- **Request Headers**:
  - `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "target_url": "https://example.com"
  }
  ```
- **Status Codes**:
  - `202 Accepted`: Scan accepted, persisted in database as `QUEUED`, and dispatched to Celery task queue.
  - `413 Payload Too Large`: Request body exceeds 64KB.
  - `422 Unprocessable Content`: URL syntax malformed, non-HTTP scheme, or private IP blocked by SSRF filter.
  - `429 Too Many Requests`: Rate limit exceeded. Returns `Retry-After` header.
  - `500 Internal Server Error`: Backend task queue or persistence failure.
- **Example cURL**:
  ```bash
  curl -X POST http://localhost:8000/api/scans \
    -H "Content-Type: application/json" \
    -d '{"target_url": "https://example.com"}'
  ```
- **Example Response (202 Accepted)**:
  ```json
  {
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "target_url": "https://example.com",
    "status": "QUEUED",
    "message": "Scan queued successfully."
  }
  ```
- **Example Error Response (422 Unprocessable Content)**:
  ```json
  {
    "detail": "Invalid target URL: Target resolves to forbidden local/private IP address."
  }
  ```
- **Example Rate Limit Response (429 Too Many Requests)**:
  ```json
  {
    "detail": "Too many scan creation requests. Limit: 10 per 60s. Retry after 45s."
  }
  ```

---

### 3. `GET /api/scans/{scan_id}/status`
Polls the real-time execution lifecycle status of an asynchronous scan.

- **Method**: `GET`
- **Path**: `/api/scans/{scan_id}/status`
- **Path Parameters**:
  - `scan_id` (string, required): UUID4 of the scan job.
- **Status Codes**:
  - `200 OK`: Status retrieved successfully.
  - `404 Not Found`: Scan ID does not exist in database.
- **Example cURL**:
  ```bash
  curl -s http://localhost:8000/api/scans/3fa85f64-5717-4562-b3fc-2c963f66afa6/status
  ```
- **Example Response (200 OK - In Progress)**:
  ```json
  {
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "status": "RUNNING"
  }
  ```
- **Example Response (200 OK - Completed)**:
  ```json
  {
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "status": "COMPLETED"
  }
  ```

---

### 4. `GET /api/scans/{scan_id}`
Retrieves the complete technical report, telemetry, findings, and remediation guidance for a scan.

- **Method**: `GET`
- **Path**: `/api/scans/{scan_id}`
- **Path Parameters**:
  - `scan_id` (string, required): UUID4 of the scan job.
- **Status Codes**:
  - `200 OK`: Report retrieved successfully.
  - `404 Not Found`: Scan ID does not exist in database.
- **Example cURL**:
  ```bash
  curl -s http://localhost:8000/api/scans/3fa85f64-5717-4562-b3fc-2c963f66afa6
  ```
- **Example Response (200 OK)**:
  ```json
  {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "target_url": "https://example.com",
    "status": "COMPLETED",
    "score": 85,
    "grade": "B",
    "created_at": "2026-08-17T14:00:00Z",
    "started_at": "2026-08-17T14:00:01Z",
    "completed_at": "2026-08-17T14:00:03Z",
    "result": {
      "summary": {
        "total": 9,
        "passed": 7,
        "failed": 2,
        "warnings": 0
      },
      "http": {
        "status_code": 200,
        "response_time": 0.182,
        "redirect_chain": ["https://example.com/"]
      },
      "tls": {
        "status": "PASS",
        "connection": {
          "version": "TLSv1.3",
          "cipher_suite": "TLS_AES_256_GCM_SHA384"
        }
      },
      "cms": {
        "detected": false,
        "cms": null
      },
      "findings": [
        {
          "id": "HDR_CSP",
          "name": "Content-Security-Policy Header",
          "category": "security_headers",
          "status": "FAIL",
          "severity": "MEDIUM",
          "points": -10,
          "description": "Restricts sources of content loaded on the page.",
          "details": "Missing Content-Security-Policy header in HTTP response.",
          "remediation": {
            "why_it_matters": "Mitigates Cross-Site Scripting (XSS) and data injection attacks.",
            "recommendation": "Define a strict policy with default-src and script-src.",
            "configuration_examples": {
              "Nginx": "add_header Content-Security-Policy \"default-src 'self';\" always;",
              "Apache": "Header always set Content-Security-Policy \"default-src 'self';\"",
              "Caddy": "header Content-Security-Policy \"default-src 'self';\""
            }
          }
        }
      ]
    },
    "error": null
  }
  ```

---

### 5. `GET /api/scans/{scan_id}/report/pdf`
Compiles and streams a downloadable, executive multi-page PDF security report for completed scans.

- **Method**: `GET`
- **Path**: `/api/scans/{scan_id}/report/pdf`
- **Path Parameters**:
  - `scan_id` (string, required): UUID4 of the scan job.
- **Status Codes**:
  - `200 OK`: Binary PDF stream returned.
  - `404 Not Found`: Scan ID does not exist in database.
  - `409 Conflict`: Scan is still `QUEUED` / `RUNNING` or marked `FAILED`.
- **Response Headers**:
  - `Content-Type: application/pdf`
  - `Content-Disposition: attachment; filename="vulnscan-report-<scan_id>.pdf"`
- **Example cURL**:
  ```bash
  curl -O -J http://localhost:8000/api/scans/3fa85f64-5717-4562-b3fc-2c963f66afa6/report/pdf
  ```

---

### 6. `GET /api/scans`
Returns a paginated list of historical scan summaries from the database.

- **Method**: `GET`
- **Path**: `/api/scans`
- **Query Parameters**:
  - `limit` (integer, default: 50, min: 1, max: 100): Maximum records to return.
  - `offset` (integer, default: 0, min: 0): Records to skip for pagination.
- **Status Codes**:
  - `200 OK`: List of scans retrieved successfully.
- **Example cURL**:
  ```bash
  curl -s "http://localhost:8000/api/scans?limit=10&offset=0"
  ```
- **Example Response (200 OK)**:
  ```json
  {
    "total": 1,
    "items": [
      {
        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "target_url": "https://example.com",
        "status": "COMPLETED",
        "score": 85,
        "grade": "B",
        "created_at": "2026-08-17T14:00:00Z",
        "started_at": "2026-08-17T14:00:01Z",
        "completed_at": "2026-08-17T14:00:03Z"
      }
    ]
  }
  ```
