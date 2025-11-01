from __future__ import absolute_import, unicode_literals
import os
from celery.schedules import crontab
from celery import Celery
from django.conf import settings
# from hrmanagementapp.tasks import send_bulk_emails
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'virustotalproject.settings')

app = Celery('virustotalproject')
app.conf.enable_utc = True

app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

# app.conf.beat_schedule = {
#     'refresh-data-everyday': {
#         'task': 'virustotalproject.tasks.refresh_virus_total_data',
#         'schedule': crontab(hour=6, minute=0),
#     }
# }



app.conf.beat_schedule = {
    'run-every-minute': {
        'task': 'virustotalapp.tasks.refresh_virus_total_data',  # Replace with your actual module path
        'schedule': crontab(minute="*")  # Runs every 1 minute
    },
}

# app.conf.update(
#     worker_concurrency=5,  # Adjust based on server capability
#     task_acks_late=True,  # Ensures tasks are not lost if a worker crashes
#     worker_prefetch_multiplier=1  # Ensures fair task distribution
# )
