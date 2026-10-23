import json
import re
import secrets
from datetime import timedelta, timezone
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, ConfigDict, field_validator
from sqlalchemy import select, or_, delete
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from fastapi.responses import JSONResponse
from .db import (
    db,
    User,
    LoginSession,
    LoginAttempt,
    Upload,
    Case,
    Activity,
    audit,
    now,
    utc,
)
from .security import current, admin, passwords, DUMMY, digest, COOKIE_SECURE
from .schema import parse_logs

app = FastAPI(
    title="IncidentDesk",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)
MAX_UPLOAD = 5 * 1024 * 1024


@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc):
    # SQL exceptions can contain bound parameters; never send or log them.
    return JSONResponse(
        status_code=503,
        content={"detail": "Database operation unavailable. Please retry."},
    )


@app.middleware("http")
async def headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/api/health")
def health(s=Depends(db)):
    from sqlalchemy import text

    s.execute(text("SELECT 1"))
    return {"status": "ok"}


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)


class NewUser(Credentials):
    password: str = Field(min_length=12, max_length=256)
    role: Literal["analyst", "administrator"] = "analyst"


def user_dict(user):
    return dict(id=user.id, username=user.username, role=user.role)


@app.post("/api/auth/login")
def login(body: Credentials, request: Request, response: Response, s=Depends(db)):
    # Database-backed per-source throttle; forwarded headers are deliberately ignored.
    key = digest(request.client.host if request.client else "unknown")
    attempt = s.scalar(
        select(LoginAttempt).where(LoginAttempt.key == key).with_for_update()
    )
    if not attempt:
        attempt = LoginAttempt(key=key, count=0, window=now())
        s.add(attempt)
        try:
            s.flush()
        except IntegrityError:
            s.rollback()
            attempt = s.scalar(
                select(LoginAttempt).where(LoginAttempt.key == key).with_for_update()
            )
    if utc(attempt.window) < now() - timedelta(minutes=5):
        attempt.count, attempt.window = 0, now()
    if attempt.count >= 20:
        raise HTTPException(
            429, "Too many sign-in attempts. Try again in five minutes."
        )
    attempt.count += 1
    s.commit()
    user = s.scalar(select(User).where(User.username == body.username))
    if not passwords.verify(body.password, user.password if user else DUMMY):
        raise HTTPException(401, "Invalid username or password.")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    s.execute(delete(LoginSession).where(LoginSession.expires < now()))
    s.add(
        LoginSession(
            token=digest(token),
            csrf=csrf,
            user_id=user.id,
            expires=now() + timedelta(hours=8),
        )
    )
    audit(s, user.username, "login", "Signed in")
    s.commit()
    response.set_cookie(
        "incidentdesk_session",
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=28800,
        path="/",
    )
    return dict(user=user_dict(user), csrf=csrf)


@app.get("/api/auth/me")
def me(request: Request, user=Depends(current)):
    return dict(user=user_dict(user), csrf=request.state.session.csrf)


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, user=Depends(current), s=Depends(db)):
    s.delete(request.state.session)
    audit(s, user.username, "logout", "Signed out")
    s.commit()
    response.delete_cookie("incidentdesk_session", path="/")
    return {"ok": True}


@app.get("/api/users")
def users(user=Depends(current), s=Depends(db)):
    return [user_dict(u) for u in s.scalars(select(User).order_by(User.username))]


@app.post("/api/users", status_code=201)
def create_user(body: NewUser, user=Depends(admin), s=Depends(db)):
    new = User(
        username=body.username, password=passwords.hash(body.password), role=body.role
    )
    s.add(new)
    audit(s, user.username, "user_created", f"Created {body.username} as {body.role}")
    try:
        s.commit()
    except IntegrityError:
        s.rollback()
        raise HTTPException(409, "Username already exists.") from None
    return user_dict(new)


def upload_dict(u):
    return {
        k: getattr(u, k)
        for k in (
            "id",
            "filename",
            "status",
            "event_count",
            "synthetic",
            "error",
            "attempts",
            "created",
        )
    } | {"payload_retained": u.payload is not None}


@app.post("/api/uploads", status_code=201)
async def upload(request: Request, user=Depends(current), s=Depends(db)):
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > MAX_UPLOAD:
            raise HTTPException(413, "Upload exceeds the 5 MiB limit.")
    try:
        events, sha = parse_logs(bytes(raw))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    filename = request.headers.get("x-filename", "security-events.jsonl")
    filename = re.sub(r"[^a-zA-Z0-9_.-]", "_", filename)[:120] or "events.jsonl"
    item = Upload(
        filename=filename,
        digest=sha,
        owner_id=user.id,
        payload=events,
        event_count=len(events),
        synthetic=request.headers.get("x-synthetic") == "true",
    )
    s.add(item)
    try:
        s.flush()
        audit(
            s,
            user.username,
            "upload_created",
            f"Upload {item.id}: {len(events)} records",
        )
        s.commit()
    except IntegrityError:
        s.rollback()
        existing = s.scalar(select(Upload).where(Upload.digest == sha))
        raise HTTPException(
            409,
            f"Duplicate upload: #{existing.id} is {existing.status}. No new job was created.",
        ) from None
    return upload_dict(item)


@app.get("/api/uploads")
def uploads(user=Depends(current), s=Depends(db)):
    return [
        upload_dict(u)
        for u in s.scalars(select(Upload).order_by(Upload.id.desc()).limit(200))
    ]


@app.post("/api/uploads/{upload_id}/retry")
def retry(upload_id: int, user=Depends(admin), s=Depends(db)):
    item = s.scalar(select(Upload).where(Upload.id == upload_id).with_for_update())
    if not item:
        raise HTTPException(404, "Upload not found.")
    if item.status != "failed" or item.payload is None:
        raise HTTPException(
            409, "Only failed uploads with retained data can be retried."
        )
    item.status, item.error = "queued", None
    audit(s, user.username, "upload_retried", f"Upload {item.id}")
    s.commit()
    return upload_dict(item)


@app.delete("/api/uploads/{upload_id}/payload")
def purge(upload_id: int, user=Depends(admin), s=Depends(db)):
    item = s.scalar(select(Upload).where(Upload.id == upload_id).with_for_update())
    if not item:
        raise HTTPException(404, "Upload not found.")
    if item.status in ("queued", "processing"):
        raise HTTPException(
            409, "Wait for processing to finish before deleting the retained input."
        )
    item.payload = None
    audit(
        s,
        user.username,
        "upload_payload_deleted",
        f"Upload {item.id}; case evidence and digest retained",
    )
    s.commit()
    return upload_dict(item)


def case_dict(c):
    return {
        k: getattr(c, k)
        for k in (
            "id",
            "title",
            "host",
            "username",
            "severity",
            "status",
            "assignee_id",
            "version",
            "synthetic",
            "created",
        )
    } | {"finding_count": len(c.findings), "evidence_count": len(c.evidence)}


def get_case(s, case_id, lock=False):
    query = select(Case).where(Case.id == case_id)
    c = s.scalar(query.with_for_update() if lock else query)
    if not c:
        raise HTTPException(404, "Case not found.")
    return c


@app.get("/api/cases")
def cases(
    q: str = "",
    severity: str = "",
    status: str = "",
    assignee: str = "",
    user=Depends(current),
    s=Depends(db),
):
    query = select(Case)
    if q:
        query = query.where(Case.title.ilike("%" + q[:120] + "%"))
    if severity:
        query = query.where(Case.severity == severity)
    if status:
        query = query.where(Case.status == status)
    if assignee == "unassigned":
        query = query.where(Case.assignee_id.is_(None))
    elif assignee.isdigit():
        query = query.where(Case.assignee_id == int(assignee))
    return [case_dict(c) for c in s.scalars(query.order_by(Case.id.desc()).limit(200))]


@app.get("/api/cases/{case_id}")
def detail(case_id: int, user=Depends(current), s=Depends(db)):
    c = get_case(s, case_id)
    activities = list(
        s.scalars(
            select(Activity).where(Activity.case_id == case_id).order_by(Activity.id)
        )
    )
    return case_dict(c) | {
        "evidence": c.evidence,
        "findings": c.findings,
        "activities": [
            {
                "id": a.id,
                "actor": a.actor,
                "kind": a.kind,
                "detail": a.detail,
                "created": a.created,
            }
            for a in activities
        ],
    }


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int
    status: Literal["open", "investigating", "resolved", "closed"] | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    assignee_id: int | None = None


TRANSITIONS = {
    "open": {"investigating"},
    "investigating": {"open", "resolved"},
    "resolved": {"investigating", "closed"},
    "closed": {"investigating"},
}


@app.patch("/api/cases/{case_id}")
def change(case_id: int, body: Change, user=Depends(current), s=Depends(db)):
    c = get_case(s, case_id, lock=True)
    if c.version != body.version:
        raise HTTPException(409, "This case changed. Refresh before saving.")
    for field in ("status", "severity", "assignee_id"):
        if field not in body.model_fields_set:
            continue
        value, before = getattr(body, field), getattr(c, field)
        if value == before:
            continue
        if field == "status":
            if value not in TRANSITIONS[c.status]:
                raise HTTPException(409, "Invalid status transition.")
            if (
                c.status == "closed" or value == "closed"
            ) and user.role != "administrator":
                raise HTTPException(
                    403, "Only administrators can close or reopen closed cases."
                )
        if field == "severity" and value is None:
            raise HTTPException(422, "Severity cannot be null.")
        if field == "assignee_id" and value is not None and not s.get(User, value):
            raise HTTPException(422, "Assignee does not exist.")
        setattr(c, field, value)
        audit(
            s,
            user.username,
            field + "_changed",
            json.dumps({"from": before, "to": value}),
            c.id,
        )
    c.version += 1
    s.commit()
    return case_dict(c)


class Comment(BaseModel):
    text: str = Field(min_length=1, max_length=5000)

    @field_validator("text")
    @classmethod
    def reject_null_bytes(cls, value):
        if "\x00" in value:
            raise ValueError("Null bytes are not supported")
        return value


@app.post("/api/cases/{case_id}/comments", status_code=201)
def comment(case_id: int, body: Comment, user=Depends(current), s=Depends(db)):
    get_case(s, case_id)
    if not body.text.strip():
        raise HTTPException(422, "Comment cannot be blank.")
    audit(s, user.username, "comment", body.text, case_id)
    s.commit()
    return {"ok": True}


@app.get("/api/cases/{case_id}/report")
def report(
    case_id: int,
    format: Literal["json", "markdown"] = "markdown",
    user=Depends(current),
    s=Depends(db),
):
    data = detail(case_id, user, s)
    data["assessment"] = (
        "Rule matches require analyst validation. Intent, compromise and exfiltration are not established by these heuristics."
    )
    audit(s, user.username, "report_exported", f"Exported {format}", case_id)
    s.commit()
    if format == "json":
        return Response(
            json.dumps(data, default=str, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="incident-{case_id}.json"'
            },
        )

    def safe(value):
        # Escape Markdown/HTML metacharacters in all untrusted report content.
        import html

        return re.sub(
            r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", html.escape(str(value))
        ).replace("\n", " ")

    lines = [
        f"# IncidentDesk report · Case {case_id}",
        "",
        "SYNTHETIC DEMO DATA"
        if data["synthetic"]
        else "USER-SUPPLIED DATA — provenance not verified",
        "",
        f"Status: {data['status']} | Severity: {data['severity']}",
        "",
        safe(data["title"]),
        "",
        data["assessment"],
        "",
        "## Detection observations",
    ]
    for f in data["findings"]:
        lines += [
            f"- {safe(f['title'])}: {safe(f['description'])} [{', '.join(f['evidence_ids'])}]"
        ]
    lines += ["", "## Evidence timeline"]
    for e in data["evidence"]:
        lines += [
            f"- [{e['evidence_id']}] {safe(e['timestamp'])} — {safe(json.dumps(e, ensure_ascii=False))}"
        ]
    lines += ["", "## Analyst notes and audit trail"]
    for a in data["activities"]:
        lines += [
            f"- {safe(a['created'])} · {safe(a['actor'])} · {safe(a['kind'])}: {safe(a['detail'])}"
        ]
    return Response(
        "\n".join(lines),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="incident-{case_id}.md"'
        },
    )


@app.get("/api/audit")
def system_audit(user=Depends(admin), s=Depends(db)):
    return [
        {
            "id": a.id,
            "actor": a.actor,
            "kind": a.kind,
            "detail": a.detail,
            "created": a.created,
        }
        for a in s.scalars(select(Activity).order_by(Activity.id.desc()).limit(200))
    ]


@app.post("/api/cases/{case_id}/draft")
def prepare_draft(case_id: int, user=Depends(current), s=Depends(db)):
    from .drafting import draft

    c = get_case(s, case_id)
    result = draft(c)
    audit(
        s,
        user.username,
        "draft_prepared",
        result["source"] + "; analyst review required",
        case_id,
    )
    s.commit()
    return result
