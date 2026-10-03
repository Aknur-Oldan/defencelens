import time
import logging
from datetime import datetime, timezone, timedelta
from redis import Redis
from rq import Queue, Retry
from rq.job import Job
from rq.exceptions import NoSuchJobError
from sqlalchemy import select
from app.config import settings
from app.db import Session
from app.models import Scan, now

logging.basicConfig(level=logging.INFO)
connection = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
queue = Queue("scans", connection=connection)

def dispatch():
    with Session() as db:
        scans = db.scalars(select(Scan).where(Scan.status.in_(["pending", "queued", "running", "retrying"])).with_for_update(skip_locked=True))
        for scan in scans:
            try:
                job = Job.fetch(scan.id, connection=connection)
                status = job.get_status(refresh=True)
            except NoSuchJobError:
                job, status = None, None
            if status in ("failed", "stopped", "canceled") and scan.status != "pending":
                scan.status = "failed"
                scan.error = scan.error or "Worker did not finish the job. Retry is available."
                scan.updated_at = now()
            elif scan.status == "pending" or job is None:
                if job and status in ("queued", "started", "scheduled", "deferred"):
                    scan.status = "queued"
                    continue
                if job:
                    job.delete()
                queue.enqueue("app.jobs.scan_image", scan.id, job_id=scan.id, job_timeout=540,
                              retry=Retry(max=2, interval=[15, 45]), result_ttl=86400, failure_ttl=604800)
                scan.status, scan.updated_at = "queued", now()
            elif status == "finished" and scan.status != "completed":
                scan.status, scan.error = "failed", "The job finished without a saved result. Retry the scan."
        db.commit()

if __name__ == "__main__":
    while True:
        try:
            dispatch()
        except Exception as exc:
            logging.warning("Dispatcher unavailable: %s", type(exc).__name__)
        time.sleep(5)
