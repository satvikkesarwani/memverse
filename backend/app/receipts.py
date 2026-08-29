"""Tamper-evident receipt chain (hash-linked, append-only).

current_hash = SHA256(canonical_event_data || "|" || previous_event_hash)

Verification recomputes the hash from canonical data and the previous hash,
and validates the chain walk from GENESIS. All deterministic.
"""
import hashlib
import json
from db import get_meta, set_meta, execute, q
from models import Receipt


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def canonical_event_data(event: dict) -> str:
    """The exact field set that defines the event (no id, no hashes)."""
    return canonical_json({
        "event_type": event.get("event_type"),
        "timestamp": event.get("timestamp"),
        "purpose": event.get("purpose"),
        "destination": event.get("destination"),
        "decision": event.get("decision"),
        "fields_detected": event.get("fields_detected"),
        "fields_transformed": event.get("fields_transformed"),
        "policy_version": event.get("policy_version"),
        "passport_id": event.get("passport_id"),
        "revocation_state": event.get("revocation_state"),
        "extra": event.get("extra") or {},
    })


def compute_hash(event: dict, previous_hash: str) -> str:
    return sha256_hex(canonical_event_data(event) + "|" + previous_hash)


def create_receipt(event: dict) -> Receipt:
    """Append an event to the ledger and return its receipt."""
    prev = get_meta("last_receipt_hash") or "GENESIS"
    event = dict(event)
    event.setdefault("extra", {})
    h = compute_hash(event, prev)
    receipt_id = event.get("event_id") or f"evt_{hash(h[:16]) & 0xffffffff:08x}"

    execute(
        """INSERT OR REPLACE INTO receipts
           (id, event_type, ts, decision, policy_version, memory_id, destination,
            previous_event_hash, event_hash, data_json)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (receipt_id, event.get("event_type"), event.get("timestamp"),
         event.get("decision"), event.get("policy_version"), event.get("memory_id"),
         event.get("destination"), prev, h, canonical_json(event)),
    )
    execute(
        """INSERT OR REPLACE INTO events
           (id, event_type, ts, decision, policy_version, memory_id, destination, receipt_id, latency_ms, extra)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (receipt_id, event.get("event_type"), event.get("timestamp"),
         event.get("decision"), event.get("policy_version"), event.get("memory_id"),
         event.get("destination"), receipt_id, event.get("latency_ms"), canonical_json(event.get("extra") or {})),
    )
    set_meta("last_receipt_hash", h)

    return Receipt(
        event_id=receipt_id,
        event_type=event.get("event_type", ""),
        timestamp=event.get("timestamp", ""),
        purpose=event.get("purpose", ""),
        destination=event.get("destination", ""),
        decision=event.get("decision", ""),
        fields_detected=int(event.get("fields_detected") or 0),
        fields_transformed=int(event.get("fields_transformed") or 0),
        policy_version=event.get("policy_version", ""),
        passport_id=event.get("passport_id", ""),
        previous_event_hash=prev,
        event_hash=h,
        revocation_state=event.get("revocation_state", ""),
        extra=event.get("extra") or {},
    )


def get_receipt(receipt_id: str) -> dict | None:
    rows = q("SELECT * FROM receipts WHERE id=?", (receipt_id,))
    if not rows:
        return None
    r = rows[0]
    r["data"] = json.loads(r["data_json"])
    return r


def verify_receipt(receipt_id: str) -> dict:
    """Recompute the hash and validate the chain up to this receipt."""
    r = get_receipt(receipt_id)
    if r is None:
        return {"receipt_id": receipt_id, "verified": False, "reason": "receipt not found"}

    data = json.loads(r["data_json"])
    recomputed = compute_hash(data, r["previous_event_hash"])
    hash_ok = recomputed == r["event_hash"]

    # walk the chain back to GENESIS
    chain_ok = True
    chain_len = 0
    cursor = r["previous_event_hash"]
    guard = 0
    while cursor and cursor != "GENESIS" and guard < 10000:
        rows = q("SELECT data_json, previous_event_hash, event_hash FROM receipts WHERE event_hash=?", (cursor,))
        if not rows:
            chain_ok = False
            break
        prev_data = json.loads(rows[0]["data_json"])
        if compute_hash(prev_data, rows[0]["previous_event_hash"]) != rows[0]["event_hash"]:
            chain_ok = False
            break
        cursor = rows[0]["previous_event_hash"]
        chain_len += 1
        guard += 1
    if cursor != "GENESIS":
        chain_ok = False

    verified = hash_ok and chain_ok
    return {
        "receipt_id": receipt_id,
        "verified": verified,
        "hash_ok": hash_ok,
        "chain_ok": chain_ok,
        "chain_length": chain_len,
        "previous_event_hash": r["previous_event_hash"],
        "event_hash": r["event_hash"],
        "recomputed_hash": recomputed,
        "event_type": r["event_type"],
        "decision": r["decision"],
        "timestamp": r["ts"],
        "policy_version": r["policy_version"],
    }


def ledger_recent(limit: int = 200) -> list[dict]:
    rows = q(
        "SELECT * FROM receipts ORDER BY rowid DESC LIMIT ?", (limit,))
    return [dict(r) for r in reversed(rows)]
