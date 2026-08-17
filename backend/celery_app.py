"""
Celery Application Initialization and Configuration for VulnScan Lite.
"""

import os
from celery import Celery
from backend.app.config import settings

# Initialize Celery app instance
celery_app = Celery(
    "vulnscan",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["backend.tasks"],
)

# Celery Configuration Settings
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=60,  # Hard task limit in seconds
    task_soft_time_limit=45,  # Soft task limit in seconds
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

if __name__ == "__main__":
    celery_app.start()
