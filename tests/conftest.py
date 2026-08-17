"""
Shared Pytest configuration and fixtures for VulnScan Lite test suite.
"""

from typing import Generator
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.celery_app import celery_app

# Shared in-memory SQLite database
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db() -> Generator[Session, None, None]:
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def db_session_fixture():
    """Ensure clean schema for every test and set Celery eager mode."""
    Base.metadata.create_all(bind=test_engine)
    celery_app.conf.task_always_eager = True
    yield
    Base.metadata.drop_all(bind=test_engine)
    celery_app.conf.task_always_eager = False
