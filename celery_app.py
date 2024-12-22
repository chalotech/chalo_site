from celery import Celery
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Create Celery app
celery = Celery('chalo_site',
                broker=os.getenv('CELERY_BROKER_URL'),
                backend=os.getenv('CELERY_RESULT_BACKEND'))

# Configure Celery
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# Import tasks
from tasks import *

if __name__ == '__main__':
    celery.start()
