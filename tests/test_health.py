"""
Test suite for FastAPI health check endpoint.
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_check_returns_ok():
    """
    Verify GET /health returns HTTP 200 with {"status": "healthy"}.
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
