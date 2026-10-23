import os
from pathlib import Path
import pytest
from sqlalchemy import text
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ["COOKIE_SECURE"] = "false"
from app.db import Base, engine, Session, User
from app.security import passwords
from app.main import app

if engine.dialect.name == "postgresql" and not engine.url.database.endswith("_test"):
    raise RuntimeError(
        "Refusing to reset a PostgreSQL database whose name does not end in _test."
    )


@pytest.fixture(autouse=True)
def database():
    # TEST DATABASE ONLY. CI uses a dedicated PostgreSQL service.
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with Session.begin() as s:
        s.add_all(
            [
                User(
                    username="admin",
                    password=passwords.hash("Test-admin-password!"),
                    role="administrator",
                ),
                User(
                    username="analyst",
                    password=passwords.hash("Test-analyst-password!"),
                    role="analyst",
                ),
            ]
        )
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def analyst(client):
    r = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Test-analyst-password!"},
    )
    assert r.status_code == 200
    client.headers["X-CSRF-Token"] = r.json()["csrf"]
    return client


@pytest.fixture
def admin_client(client):
    r = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Test-admin-password!"},
    )
    assert r.status_code == 200
    client.headers["X-CSRF-Token"] = r.json()["csrf"]
    return client


@pytest.fixture
def logs():
    return (
        Path(__file__).resolve().parents[2] / "data" / "synthetic-events.jsonl"
    ).read_bytes()
