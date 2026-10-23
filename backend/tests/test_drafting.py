import json
from types import SimpleNamespace
from app.drafting import draft
from tests.test_workflow import case_from


def test_draft_auth_and_csrf(client):
    assert client.post("/api/cases/1/draft").status_code == 401
    r = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Test-analyst-password!"},
    )
    assert client.post("/api/cases/1/draft").status_code == 403


def test_local_draft_citations(analyst, logs):
    c = case_from(analyst, logs)
    result = analyst.post(f"/api/cases/{c['id']}/draft")
    assert result.status_code == 200
    data = result.json()
    assert data["review_required"] and "no AI used" in data["source"]
    assert "Uncertainty:" in data["text"]
    for paragraph in data["text"].split("\n\n")[:-2]:
        assert paragraph.endswith("]") and "[U1-E" in paragraph


def test_model_can_only_select_known_facts(monkeypatch):
    c = SimpleNamespace(
        evidence=[
            {
                "evidence_id": "U1-E1",
                "timestamp": "2026-01-01",
                "event_id": "1",
                "host": "host",
            }
        ],
        findings=[{"evidence_ids": ["U1-E1"]}],
    )
    monkeypatch.setenv("AI_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("AI_MODEL", "test-model")

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": json.dumps({"evidence_ids": ["U1-E1"]})}

    monkeypatch.setattr("app.drafting.httpx.post", lambda *a, **k: Response())
    result = draft(c)
    assert "AI-assisted" in result["source"] and "[U1-E1]" in result["text"]
    Response.json = lambda self: {
        "response": '{"evidence_ids":["invented"],"claim":"exfiltration confirmed"}'
    }
    result = draft(c)
    assert (
        "invalid response" in result["source"]
        and "exfiltration confirmed" not in result["text"]
    )


def test_provider_failure_and_remote_rejection(monkeypatch):
    c = SimpleNamespace(evidence=[], findings=[])
    monkeypatch.setenv("AI_BASE_URL", "https://example.com")
    monkeypatch.setenv("AI_MODEL", "test")
    assert "configuration rejected" in draft(c)["source"]
    monkeypatch.setenv("AI_BASE_URL", "http://127.0.0.1:11434")

    def fail(*a, **k):
        raise RuntimeError("private provider details")

    monkeypatch.setattr("app.drafting.httpx.post", fail)
    result = draft(c)
    assert "unavailable" in result["source"] and "private provider" not in str(result)
