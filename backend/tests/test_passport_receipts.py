"""Unit tests: passport lifecycle, revocation, TTL, receipts."""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import db
from passport import create_passport, get_passport, set_state
from receipts import create_receipt, verify_receipt, canonical_event_data, compute_hash
from datetime import datetime, timedelta, timezone


def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    db.set_meta("last_receipt_hash", "GENESIS")


# ----------------------------------------------------------------- passport
def test_passport_created(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    p = create_passport("mem_1", "HIGH", "personalization", "GRANTED",
                        "assistant_context", 7, '{"a":1}', "v1.4")
    assert p.revocation_state == "ACTIVE"
    got = get_passport("mem_1")
    assert got is not None and got.revocation_state == "ACTIVE"
    assert got.integrity_hash == p.integrity_hash


def test_revocation_state(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    create_passport("mem_1", "MEDIUM", "personalization", "GRANTED",
                    "assistant_context", 7, "{}", "v1.4")
    set_state("mem_1", "REVOKED")
    assert get_passport("mem_1").revocation_state == "REVOKED"


def test_ttl_expiry_fails_closed(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    create_passport("mem_2", "LOW", "personalization", "GRANTED",
                    "assistant_context", 7, "{}", "v1.4")
    # rewrite as already-expired
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="milliseconds")
    db.execute("UPDATE passports SET expires_at=? WHERE memory_id=?", (past, "mem_2"))
    got = get_passport("mem_2")
    assert got.revocation_state == "EXPIRED"


# ----------------------------------------------------------------- receipts
def test_receipt_hash_chain(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    r1 = create_receipt({"event_id": "e1", "event_type": "WRITE", "timestamp": "t1",
                         "purpose": "p", "destination": "nvidia", "decision": "ALLOW",
                         "fields_detected": 2, "fields_transformed": 1,
                         "policy_version": "v1.4", "passport_id": "m1",
                         "revocation_state": "ACTIVE"})
    r2 = create_receipt({"event_id": "e2", "event_type": "REVOKE", "timestamp": "t2",
                         "purpose": "p", "destination": "nvidia", "decision": "REVOKE",
                         "fields_detected": 2, "fields_transformed": 0,
                         "policy_version": "v1.4", "passport_id": "m1",
                         "revocation_state": "REVOKED"})
    assert r1.previous_event_hash == "GENESIS"
    assert r2.previous_event_hash == r1.event_hash
    assert r1.event_hash != r2.event_hash
    # hash is a deterministic function of the event's canonical data + previous hash
    ev1 = {"event_id": "e1", "event_type": "WRITE", "timestamp": "t1", "purpose": "p",
           "destination": "nvidia", "decision": "ALLOW", "fields_detected": 2,
           "fields_transformed": 1, "policy_version": "v1.4", "passport_id": "m1",
           "revocation_state": "ACTIVE"}
    assert r1.event_hash == compute_hash(ev1, "GENESIS")
    assert r1.event_hash == compute_hash(ev1, "GENESIS")  # deterministic


def test_receipt_verify_recomputes_hash(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    r = create_receipt({"event_id": "e1", "event_type": "WRITE", "timestamp": "t1",
                        "purpose": "p", "destination": "nvidia", "decision": "ALLOW",
                        "fields_detected": 0, "fields_transformed": 0,
                        "policy_version": "v1.4", "passport_id": "", "revocation_state": "ACTIVE"})
    v = verify_receipt(r.event_id)
    assert v["verified"] is True
    assert v["recomputed_hash"] == r.event_hash
    assert v["chain_length"] >= 0


def test_receipt_tamper_detected(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    r = create_receipt({"event_id": "e1", "event_type": "WRITE", "timestamp": "t1",
                        "purpose": "p", "destination": "nvidia", "decision": "ALLOW",
                        "fields_detected": 0, "fields_transformed": 0,
                        "policy_version": "v1.4", "passport_id": "", "revocation_state": "ACTIVE"})
    # tamper: flip the stored decision in the data_json
    row = db.q("SELECT data_json FROM receipts WHERE id=?", (r.event_id,))[0]
    data = json.loads(row["data_json"])
    data["decision"] = "BLOCK"
    db.execute("UPDATE receipts SET data_json=? WHERE id=?", (json.dumps(data), r.event_id))
    v = verify_receipt(r.event_id)
    assert v["verified"] is False
    assert v["hash_ok"] is False


def test_receipt_chain_break_detected(tmp_path, monkeypatch):
    _fresh_db(tmp_path, monkeypatch)
    r1 = create_receipt({"event_id": "e1", "event_type": "WRITE", "timestamp": "t1",
                         "purpose": "p", "destination": "nvidia", "decision": "ALLOW",
                         "fields_detected": 0, "fields_transformed": 0,
                         "policy_version": "v1.4", "passport_id": "", "revocation_state": "ACTIVE"})
    r2 = create_receipt({"event_id": "e2", "event_type": "READ", "timestamp": "t2",
                         "purpose": "p", "destination": "nvidia", "decision": "ALLOW",
                         "fields_detected": 0, "fields_transformed": 0,
                         "policy_version": "v1.4", "passport_id": "", "revocation_state": "ACTIVE"})
    # break the chain by rewriting r1's data
    row = db.q("SELECT data_json FROM receipts WHERE id=?", (r1.event_id,))[0]
    data = json.loads(row["data_json"])
    data["extra"] = {"hacked": True}
    db.execute("UPDATE receipts SET data_json=? WHERE id=?", (json.dumps(data), r1.event_id))
    v = verify_receipt(r2.event_id)
    assert v["verified"] is False
    assert v["chain_ok"] is False


def test_canonical_json_deterministic():
    a = canonical_event_data({"b": 1, "a": 2, "c": [3, 1]})
    b = canonical_event_data({"c": [3, 1], "b": 1, "a": 2})
    assert a == b
