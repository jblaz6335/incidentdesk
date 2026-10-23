import time
import secrets
from datetime import timedelta
from sqlalchemy import select
from .db import Session, Upload, Case, audit, now
from .detection import correlate

def run_once(processor=correlate):
    with Session.begin() as s:
        # Lock before lease recovery so a live finalization cannot race recovery.
        for old in s.scalars(select(Upload).where(Upload.status == 'processing', Upload.started < now() - timedelta(minutes=5)).with_for_update(skip_locked=True)):
            old.status, old.error, old.lease = 'failed', 'Worker lease expired. An administrator can retry.', None
            audit(s, 'worker', 'upload_failed', f'Upload {old.id}: lease expired')
        job = s.scalar(select(Upload).where(Upload.status == 'queued').order_by(Upload.id).with_for_update(skip_locked=True).limit(1))
        if not job:
            return False
        job.status, job.started, job.lease = 'processing', now(), secrets.token_hex(16)
        job.attempts += 1
        job_id, lease, payload, synthetic = job.id, job.lease, job.payload, job.synthetic
    try:
        result = processor(payload, job_id)
        with Session.begin() as s:
            job = s.scalar(select(Upload).where(Upload.id == job_id).with_for_update())
            if job.status != 'processing' or job.lease != lease:
                return True
            for data in result:
                case = Case(upload_id=job_id, synthetic=synthetic, **data)
                s.add(case)
                s.flush()
                audit(s, 'worker', 'case_created', f'Correlated {len(data["findings"])} rule matches from upload {job_id}; analyst validation required.', case.id)
            job.status, job.error, job.lease = 'completed', None, None
            audit(s, 'worker', 'upload_completed', f'Upload {job_id}: {len(result)} cases')
    except Exception:
        # Never log raw exceptions: drivers/providers may include evidence or secrets.
        with Session.begin() as s:
            job = s.scalar(select(Upload).where(Upload.id == job_id).with_for_update())
            if job.lease == lease and job.status == 'processing':
                job.status, job.error, job.lease = 'failed', 'Processing failed. An administrator can retry the retained upload.', None
                audit(s, 'worker', 'upload_failed', f'Upload {job_id}: processing failed')
    return True

if __name__ == '__main__':
    while True:
        try:
            if not run_once():
                time.sleep(2)
        except Exception:
            print('Worker database unavailable; retrying.', flush=True)
            time.sleep(5)
