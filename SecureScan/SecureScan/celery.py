import os
from celery import Celery
from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SecureScan.settings")

celery_app = Celery("myproject")
celery_app.config_from_object("django.conf:settings", namespace="CELERY")
celery_app.autodiscover_tasks()

# Celery beat settings for periodic tasks (optional)
celery_app.conf.beat_schedule = {
    "run-scheduled-scans": {
        "task": "secure_scan_api.scan.tasks.run_scan",
        "schedule": 3600.0,  # Run every hour (for example)
        "args": ["scheduled_scan_id", "all"],
    },
}
