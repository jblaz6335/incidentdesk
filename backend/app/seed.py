import os
from pathlib import Path
from sqlalchemy import select
from .db import Session, User, Upload, audit
from .security import passwords
from .schema import parse_logs


def seed():
    with Session.begin() as s:
        for name, role, variable in [
            ("admin", "administrator", "DEMO_ADMIN_PASSWORD"),
            ("analyst", "analyst", "DEMO_ANALYST_PASSWORD"),
        ]:
            if not s.scalar(select(User).where(User.username == name)):
                password = os.environ.get(variable, "")
                if len(password) < 12:
                    raise RuntimeError(f"Set {variable} to at least 12 characters.")
                s.add(User(username=name, role=role, password=passwords.hash(password)))
        s.flush()
        user = s.scalar(select(User).where(User.username == "admin"))
        path = Path(os.environ.get("DEMO_DATA", "/data/synthetic-events.jsonl"))
        payload, sha = parse_logs(path.read_bytes())
        if not s.scalar(select(Upload).where(Upload.digest == sha)):
            s.add(
                Upload(
                    digest=sha,
                    filename="synthetic-events.jsonl",
                    owner_id=user.id,
                    payload=payload,
                    event_count=len(payload),
                    synthetic=True,
                )
            )
            audit(
                s,
                "admin",
                "demo_seeded",
                "Synthetic SOC lab telemetry queued. No real incident or malware.",
            )


if __name__ == "__main__":
    seed()
