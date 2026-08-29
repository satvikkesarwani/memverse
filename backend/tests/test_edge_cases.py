"""Edge-case & consistency tests:
- API input validation (whitespace, length limits)
- multi-prompt session: every message maps to its own trace, distinct REQ numbers
- structured audit log: events carry request_id, never raw prompt values
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import pytest
from fastapi.testclient import TestClient

import db


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "edge.db"))
    db.init_db()
    from memory import reset_demo
    reset_demo()
    from api import app
    return TestClient(app)


def test_whitespace_prompt_rejected(client):
    for bad in ("", "   ", "\n\t ", " \n  "):
        r = client.post("/api/chat", json={"prompt": bad})
        assert r.status_code == 422, f"{bad!r} -> {r.status_code}"


def test_oversized_prompt_rejected(client):
    r = client.post("/api/chat", json={"prompt": "x" * 2500})
    assert r.status_code == 422


def test_valid_prompt_accepted(client):
    r = client.post("/api/chat", json={"prompt": "What is the capital of France?"})
    assert r.status_code == 200
    assert r.json()["trace"]["request_number"] == 1


def test_each_message_has_own_trace(client):
    """5 prompts in one session -> 5 traces, sequential REQ numbers, correct mapping."""
    conv = None
    ids = []
    for i, p in enumerate(["What is my name and age?",
                           "What programming language do I use?",
                           "What is my full name?",
                           "Tell me a short joke.",
                           "What do you remember about me?"]):
        body = {"prompt": p}
        if conv:
            body["conversation_id"] = conv
        r = client.post("/api/chat", json=body)
        assert r.status_code == 200
        data = r.json()
        conv = data.get("conversation_id") or conv
        ids.append((data["message_id"], data["trace"]["request_id"],
                    data["trace"]["request_number"]))
    # request numbers strictly increasing
    nums = [n for _, _, n in ids]
    assert nums == list(range(1, 6)), nums
    # every trace_id unique
    tids = [t for _, t, _ in ids]
    assert len(set(tids)) == 5
    # message_ids unique
    mids = [m for m, _, _ in ids]
    assert len(set(mids)) == 5


def test_audit_log_redaction_and_threading(client):
    """Structured log events share request_id and never contain raw prompt values."""
    r = client.post("/api/chat", json={
        "prompt": "My name is Alex and my email is alex.demo@gmail.com. What do you know?"})
    assert r.status_code == 200
    rid = r.json()["trace"]["request_id"]
    logs = client.get("/api/audit/logs?limit=100").json()["logs"]
    evs = [e for e in logs if e["request_id"] == rid]
    assert evs, "no audit events for the request"
    events = [e["event"] for e in evs]
    assert "REQUEST_RECEIVED" in events
    assert "SENSITIVE_DATA_DETECTED" in events
    assert "POLICY_EVALUATED" in events
    assert "SECURITY_RECEIPT_CREATED" in events
    blob = json.dumps(evs)
    assert "alex.demo@gmail.com" not in blob, "raw value leaked into audit log"
    assert "My name is Alex" not in blob, "raw prompt leaked into audit log"
    # no secret-shaped keys in the ring at all
    ring = client.get("/api/audit/logs?limit=500").json()["logs"]
    ring_blob = json.dumps(ring)
    for secret in ("api_key", "apikey", "authorization", "bearer ", "sk-"):
        assert secret.lower() not in ring_blob.lower()
