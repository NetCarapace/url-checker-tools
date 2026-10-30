#!/usr/bin/env python3
"""Celery application configuration for distributed URL scanning workflows."""

import os

from celery import Celery


# Celery app configuration
def create_celery_app() -> Celery:
    """Create and configure Celery application."""

    # Redis configuration from environment
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    app = Celery(
        "urlchecker_workflows",
        broker=redis_url,
        backend=redis_url,
        include=[
            "url_checker_tools.providers.whalebone",
            "url_checker_tools.providers.virustotal",
            "url_checker_tools.providers.google_sb",
            "url_checker_tools.providers.abuseipdb",
            "url_checker_tools.providers.whois",
            "url_checker_tools.providers.urlscan",
            "url_checker_tools.providers.lookyloo",
            "url_checker_tools.providers.yara",
            "url_checker_tools.providers.link_analyzer",
            "url_checker_tools.providers.misp",
            "url_checker_tools.workflows.orchestrator",
        ],
    )

    # Celery configuration
    app.conf.update(
        # Task routing
        task_routes={
            "whois_scan": {"queue": "fast_tasks"},
            "whalebone_scan": {"queue": "fast_tasks"},
            "virustotal_scan": {"queue": "api_tasks"},
            "google_sb_scan": {"queue": "api_tasks"},
            "abuseipdb_scan": {"queue": "api_tasks"},
            "urlscan_scan": {"queue": "api_tasks"},
            "misp_scan": {"queue": "api_tasks"},
            "yara_scan": {"queue": "heavy_tasks"},
            "lookyloo_scan": {"queue": "heavy_tasks"},
            "link_analyzer_scan": {"queue": "fast_tasks"},
        },
        # Worker configuration
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        # Task execution
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        # Retry configuration
        task_reject_on_worker_lost=True,
        task_always_eager=False,
        # Result expiration
        result_expires=3600,  # 1 hour
        # Task time limits
        task_soft_time_limit=300,  # 5 minutes
        task_time_limit=600,  # 10 minutes
        # Monitoring
        worker_send_task_events=True,
        task_send_sent_event=True,
    )

    return app


# Create global app instance
celery_app = create_celery_app()


# Auto-discovery of tasks
if __name__ == "__main__":
    celery_app.start()
