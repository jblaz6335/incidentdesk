import json
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import select, func
from app.db import Session, Upload, Case, LoginSession, User, now, engine
from app.worker import run_once
from app.detection import correlate
from app.schema import parse_logs

PROTECTED = [
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/logout"),
    ("GET", "/api/users"),
    ("POST", "/api/users"),
    ("GET", "/api/uploads"),
    ("POST", "/api/uploads"),
    ("POST", "/api/uploads/1/retry"),
    ("DELETE", "/api/uploads/1/payload"),
    ("GET", "/api/cases"),
    ("GET", "/api/cases/1"),
    ("PATCH", "/api/cases/1"),
    ("POST", "/api/cases/1/comments"),
    ("GET", "/api/cases/1/report"),
    ("GET", "/api/audit"),
]
PROTECTED.append(("POST", "/api/cases/1/draft"))


@pytest.mark.parametrize("method,path", PROTECTED)
def test_every_operation_requires_auth(client, method, path):
    assert client.request(method, path).status_code == 401


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/users"),
        ("POST", "/api/uploads/1/retry"),
        ("DELETE", "/api/uploads/1/payload"),
        ("GET", "/api/audit"),
    ],
)
def test_admin_boundaries(analyst, method, path):
    assert analyst.request(method, path).status_code == 403


@pytest.mark.parametrize(
    "method,path", [(m, p) for m, p in PROTECTED if m not in ("GET", "HEAD")]
)
def test_every_mutation_requires_csrf(admin_client, method, path):
    admin_client.headers.pop("X-CSRF-Token")
    assert admin_client.request(method, path).status_code == 403


def enqueue(client, logs):
    r = client.post(
        "/api/uploads",
        content=logs,
        headers={"X-Synthetic": "true", "X-Filename": "demo.jsonl"},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def case_from(client, logs):
    enqueue(client, logs)
    assert run_once()
    return client.get("/api/cases").json()[0]


def test_full_workflow(analyst, logs):
    c = case_from(analyst, logs)
    detail = analyst.get(f"/api/cases/{c['id']}").json()
    assert c["finding_count"] == 5
    assert c["synthetic"] is True
    evidence_ids = {e["evidence_id"] for e in detail["evidence"]}
    assert all(
        f["evidence_ids"] and set(f["evidence_ids"]) <= evidence_ids
        for f in detail["findings"]
    )
    changed = analyst.patch(
        f"/api/cases/{c['id']}",
        json={
            "version": c["version"],
            "status": "investigating",
            "severity": "medium",
            "assignee_id": 2,
        },
    )
    assert changed.status_code == 200
    note = '<script>alert("untrusted")</script> [U1-E0001]'
    assert (
        analyst.post(f"/api/cases/{c['id']}/comments", json={"text": note}).status_code
        == 201
    )
    detail = analyst.get(f"/api/cases/{c['id']}").json()
    assert {a["kind"] for a in detail["activities"]} >= {
        "severity_changed",
        "status_changed",
        "assignee_id_changed",
        "comment",
    }
    assert all(
        a["actor"] == "analyst"
        for a in detail["activities"]
        if a["kind"] != "case_created"
    )
    report = analyst.get(f"/api/cases/{c['id']}/report?format=json")
    assert report.status_code == 200 and report.json()["evidence"] == detail["evidence"]
    md = analyst.get(f"/api/cases/{c['id']}/report?format=markdown")
    assert (
        "SYNTHETIC DEMO DATA" in md.text
        and "<script>" not in md.text
        and "U1-E" in md.text
    )
    assert not run_once()
    assert len(analyst.get("/api/cases").json()) == 1


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b"{}",
        b"[]",
        b"\xff",
        b'{"timestamp":"2026-01-01","event_id":1,"host":"x","channel":"Security"}',
        b'{"timestamp":"2026-01-01T00:00:00Z","event_id":1,"host":"x","channel":"Security","unknown":"bad"}',
    ],
)
def test_malformed(analyst, payload):
    r = analyst.post("/api/uploads", content=payload)
    assert r.status_code == 422
    assert analyst.get("/api/uploads").json() == []


def test_limits(analyst):
    assert (
        analyst.post("/api/uploads", content=b"x" * (5 * 1024 * 1024 + 1)).status_code
        == 413
    )
    assert analyst.post("/api/uploads", content=b"{}\n" * 10001).status_code == 422


def test_duplicate_canonicalization(analyst, logs):
    enqueue(analyst, logs)
    lines = [json.loads(line) for line in logs.splitlines() if line]
    changed = "\n".join(
        json.dumps(e, sort_keys=True) for e in reversed(lines + lines[:1])
    )
    assert analyst.post("/api/uploads", content=changed).status_code == 409
    run_once()
    assert analyst.post("/api/uploads", content=logs).status_code == 409
    assert len(analyst.get("/api/uploads").json()) == 1
    assert len(analyst.get("/api/cases").json()) == 1


def test_failure_retry_and_retention(admin_client, logs):
    uid = enqueue(admin_client, logs)

    def fail(*args):
        raise RuntimeError("secret evidence must not appear in errors")

    run_once(fail)
    u = admin_client.get("/api/uploads").json()[0]
    assert u["status"] == "failed" and "secret" not in u["error"]
    assert admin_client.get("/api/cases").json() == []
    assert admin_client.post(f"/api/uploads/{uid}/retry").status_code == 200
    run_once()
    assert admin_client.post(f"/api/uploads/{uid}/retry").status_code == 409
    assert len(admin_client.get("/api/cases").json()) == 1
    assert (
        admin_client.delete(f"/api/uploads/{uid}/payload").json()["payload_retained"]
        is False
    )
    assert admin_client.post("/api/uploads", content=logs).status_code == 409
    assert len(admin_client.get("/api/cases/1").json()["evidence"]) > 0


def test_lease_recovery(admin_client, logs):
    uid = enqueue(admin_client, logs)
    with Session.begin() as s:
        u = s.get(Upload, uid)
        u.status = "processing"
        u.started = now() - timedelta(minutes=6)
        u.lease = "expired"
    run_once()
    assert admin_client.get("/api/uploads").json()[0]["status"] == "failed"
    assert admin_client.post(f"/api/uploads/{uid}/retry").status_code == 200
    run_once()
    assert len(admin_client.get("/api/cases").json()) == 1


def test_stale_worker_cannot_finalize(admin_client, logs):
    uid = enqueue(admin_client, logs)

    def stale(payload, job_id):
        with Session.begin() as s:
            u = s.get(Upload, job_id)
            u.lease = "new-lease"
            u.status = "failed"
        return correlate(payload, job_id)

    run_once(stale)
    assert admin_client.get("/api/cases").json() == []


def test_delete_queued_denied(admin_client, logs):
    uid = enqueue(admin_client, logs)
    assert admin_client.delete(f"/api/uploads/{uid}/payload").status_code == 409


def test_transitions_and_conflicts(analyst, logs):
    c = case_from(analyst, logs)
    url = f"/api/cases/{c['id']}"
    assert (
        analyst.patch(url, json={"version": 1, "status": "closed"}).status_code == 409
    )
    assert (
        analyst.patch(url, json={"version": 1, "status": "investigating"}).status_code
        == 200
    )
    assert analyst.patch(url, json={"version": 1, "severity": "low"}).status_code == 409
    assert (
        analyst.patch(url, json={"version": 2, "status": "resolved"}).status_code == 200
    )
    assert (
        analyst.patch(url, json={"version": 3, "status": "closed"}).status_code == 403
    )
    assert (
        analyst.patch(url, json={"version": 3, "assignee_id": 999}).status_code == 422
    )
    assert analyst.patch(url, json={"version": 3, "severity": None}).status_code == 422
    assert analyst.patch(url, json={"version": 3, "arbitrary": "no"}).status_code == 422


def test_administrator_close_reopen(admin_client, logs):
    c = case_from(admin_client, logs)
    for i, status in enumerate(
        ["investigating", "resolved", "closed", "investigating"], 1
    ):
        assert (
            admin_client.patch(
                f"/api/cases/{c['id']}", json={"version": i, "status": status}
            ).status_code
            == 200
        )


def test_auth_expiry_logout_and_hashes(client):
    assert (
        client.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong"}
        ).status_code
        == 401
    )
    r = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Test-admin-password!"},
    )
    assert (
        "HttpOnly" in r.headers["set-cookie"]
        and "SameSite=strict" in r.headers["set-cookie"]
    )
    client.headers["X-CSRF-Token"] = r.json()["csrf"]
    with Session() as s:
        assert s.get(User, 1).password.startswith("$argon2id$")
        assert s.scalar(select(LoginSession)).token != client.cookies.get(
            "incidentdesk_session"
        )
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Test-admin-password!"},
    )
    with Session.begin() as s:
        for token in s.scalars(select(LoginSession)):
            token.expires = now() - timedelta(seconds=1)
    assert client.get("/api/auth/me").status_code == 401


def test_throttle(client):
    for _ in range(20):
        assert (
            client.post(
                "/api/auth/login", json={"username": "missing", "password": "wrong"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/auth/login", json={"username": "missing", "password": "wrong"}
        ).status_code
        == 429
    )


def test_create_account_and_filter(admin_client, logs):
    body = {"username": "new", "password": "long-test-password", "role": "analyst"}
    assert admin_client.post("/api/users", json=body).status_code == 201
    assert admin_client.post("/api/users", json=body).status_code == 409
    assert "password" not in admin_client.get("/api/users").text
    case_from(admin_client, logs)
    assert (
        len(
            admin_client.get(
                "/api/cases?q=WS-FIN&severity=critical&status=open&assignee=unassigned"
            ).json()
        )
        == 1
    )
    assert admin_client.get("/api/cases?q=absent").json() == []
    assert admin_client.get("/api/audit").status_code == 200


def test_benign_and_window_isolation(analyst, logs):
    benign = b'{"timestamp":"2026-01-01T00:00:00Z","event_id":4624,"host":"safe","channel":"Security","outcome":"success"}'
    enqueue(analyst, benign)
    run_once()
    assert analyst.get("/api/cases").json() == []
    payload, _ = parse_logs(logs)
    auth = [
        e
        for e in payload
        if e["event_id"] in ("4624", "4625") and e["host"] == "WS-FIN-07"
    ]
    next(e for e in auth if e["event_id"] == "4624")["timestamp"] = (
        "2026-07-16T09:04:02+00:00"
    )
    assert correlate(auth, 2) == []


@pytest.mark.skipif(
    engine.dialect.name != "postgresql", reason="PostgreSQL locking semantics required"
)
def test_concurrent_workers(admin_client, logs):
    enqueue(admin_client, logs)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: run_once(), range(2)))
    assert len(admin_client.get("/api/cases").json()) == 1


def test_missing_objects(analyst):
    for suffix in ("", "/report"):
        assert analyst.get("/api/cases/999" + suffix).status_code == 404
    assert (
        analyst.post("/api/cases/999/comments", json={"text": "note"}).status_code
        == 404
    )


def test_failed_commit_rolls_back_partial_cases(admin_client, logs):
    enqueue(admin_client, logs)

    def invalid_result(payload, uid):
        good = correlate(payload, uid)[0]
        return [good, dict(good, host=None)]

    run_once(invalid_result)
    assert admin_client.get("/api/cases").json() == []
    assert admin_client.get("/api/uploads").json()[0]["status"] == "failed"


def test_null_bytes_rejected(analyst, logs):
    c = case_from(analyst, logs)
    assert (
        analyst.post(
            f"/api/cases/{c['id']}/comments", json={"text": "bad\x00note"}
        ).status_code
        == 422
    )
    raw = json.loads(logs.splitlines()[0])
    raw["host"] = "bad\x00host"
    assert analyst.post("/api/uploads", content=json.dumps(raw)).status_code == 422
