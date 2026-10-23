from app.worker.celery_app import celery_app
from app.database import SessionLocal
from app.scanners.manager import scanner_manager


@celery_app.task(bind=True, name="tasks.execute_scan_job", max_retries=1)
def execute_scan_job_task(self, scan_job_id: str):
    """
    Celery background worker task for running a scheduled or dispatched security scan job.
    """
    db = SessionLocal()
    try:
        job = scanner_manager.execute_scan_job(db, scan_job_id)
        return {
            "job_id": job.id,
            "status": job.status.value,
            "scanners_executed": len(job.executions),
            "findings_count": len(job.findings)
        }
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=10)
    finally:
        db.close()
