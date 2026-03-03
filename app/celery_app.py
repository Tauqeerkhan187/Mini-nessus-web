# Author: TK
# Date: 04-03-2026
# Purpose: create celery app

import os
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

def make_celery():
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    celery = Celery("mini-nessus-web", broker=redis_url, backend=redis_url, include=["app.tasks"],)
    celery.conf.update(task_track_started=True, broker_connection_retry_on_startup=True,)
    return celery

celery = make_celery()

