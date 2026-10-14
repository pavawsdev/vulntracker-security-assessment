import os
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import models  # noqa: E402
from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

# Helper: create a scan with internal remediation notes, to check they aren't leaked
def create_scan(token, title="Shared finding"):
    return client.post("/scans", json={
        "title": title,
        "severity": "high",
        "affected_component": "billing-api",
        "remediation_notes": "internal: patch scheduled for sprint 12",
    }, headers=auth_headers(token)).json()["id"]


# Helper: pull the raw token off the end of share_url
def share_token_from(resp):
    return resp.json()["share_url"].rsplit("/", 1)[-1]


# Happy path: link works, response isn't cached and hides internal fields
def test_share_link_without_password():
    token = register_and_login()
    scan_id = create_scan(token)

    resp = client.post(f"/scans/{scan_id}/share", headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["share_url"].startswith("http://localhost:8000/share/")

    shared = client.get(f"/share/{share_token_from(resp)}")
    assert shared.status_code == 200
    assert shared.json()["title"] == "Shared finding"
    assert shared.headers["cache-control"] == "no-store"
    # internal fields are not exposed to external recipients
    assert "owner_id" not in shared.json()
    assert "remediation_notes" not in shared.json()


# Password-protected link: missing or wrong password gets 401, correct one gets 200
def test_share_link_with_password():
    token = register_and_login()
    scan_id = create_scan(token)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "auditor-pass-1"},
                       headers=auth_headers(token))
    share_token = share_token_from(resp)

    assert client.get(f"/share/{share_token}").status_code == 401
    assert client.get(f"/share/{share_token}", params={"password": "wrong-pass"}).status_code == 401
    ok = client.get(f"/share/{share_token}", params={"password": "auditor-pass-1"})
    assert ok.status_code == 200


# Weak link passwords are rejected at creation
def test_share_link_rejects_short_password():
    token = register_and_login()
    scan_id = create_scan(token)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "short"},
                       headers=auth_headers(token))
    assert resp.status_code == 422


# IDOR check: a user can't create a share link for someone else's scan
def test_cannot_share_another_users_scan():
    owner = register_and_login()
    scan_id = create_scan(owner)
    other = register_and_login(username="mallory", email="mallory@example.com")

    resp = client.post(f"/scans/{scan_id}/share", headers=auth_headers(other))
    assert resp.status_code == 404


# Creating a link requires a logged-in user
def test_share_requires_authentication():
    owner = register_and_login()
    scan_id = create_scan(owner)
    assert client.post(f"/scans/{scan_id}/share").status_code in (401, 403)


# Made-up tokens get 404
def test_unknown_share_token():
    assert client.get("/share/not-a-real-token").status_code == 404


# Links stop working after expires_at (time is moved by editing the row)
def test_expired_share_link():
    token = register_and_login()
    scan_id = create_scan(token)
    share_token = share_token_from(client.post(f"/scans/{scan_id}/share", headers=auth_headers(token)))

    db = TestingSessionLocal()
    link = db.query(models.ShareLink).one()
    link.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    db.close()

    assert client.get(f"/share/{share_token}").status_code == 404


# The DB holds only the SHA-256 hash, never the raw token
def test_share_token_not_stored_in_plaintext():
    token = register_and_login()
    scan_id = create_scan(token)
    share_token = share_token_from(client.post(f"/scans/{scan_id}/share", headers=auth_headers(token)))

    db = TestingSessionLocal()
    link = db.query(models.ShareLink).one()
    db.close()
    assert link.token_hash != share_token
    assert len(link.token_hash) == 64


# ---------------------------------------------------------------------------
# Remediation regression tests
# ---------------------------------------------------------------------------

# F1: injection payloads return no rows and can't reach other users' data or the users table
def test_search_sql_injection_is_neutralised():
    token = register_and_login(username="carol", email="carol@example.com")
    client.post("/scans", json={"title": "Carol finding", "severity": "low",
                                "affected_component": "svc"}, headers=auth_headers(token))
    for payload in ["zz' OR '1'='1",
                    "zz' UNION SELECT id,username,hashed_password,email,'x','x','x',0,created_at FROM users--"]:
        resp = client.get("/scans/search", params={"q": payload}, headers=auth_headers(token))
        assert resp.status_code == 200
        assert resp.json()["results"] == []


# F1: search only returns the caller's own scans
def test_search_is_scoped_to_owner():
    owner = register_and_login(username="dave", email="dave@example.com")
    client.post("/scans", json={"title": "shared-term dave", "severity": "low",
                                "affected_component": "svc"}, headers=auth_headers(owner))
    other = register_and_login(username="erin", email="erin@example.com")
    client.post("/scans", json={"title": "shared-term erin", "severity": "low",
                                "affected_component": "svc"}, headers=auth_headers(other))
    resp = client.get("/scans/search", params={"q": "shared-term"}, headers=auth_headers(other))
    titles = [r["title"] for r in resp.json()["results"]]
    assert titles == ["shared-term erin"]


# F1: LIKE wildcards in user input are treated literally, not as match-all
def test_search_wildcards_are_escaped():
    token = register_and_login(username="frank", email="frank@example.com")
    client.post("/scans", json={"title": "real finding", "severity": "low",
                                "affected_component": "svc"}, headers=auth_headers(token))
    resp = client.get("/scans/search", params={"q": "%%"}, headers=auth_headers(token))
    assert resp.json()["results"] == []
