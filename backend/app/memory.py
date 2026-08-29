"""Memory store — WRITE / READ / REVOKE lifecycle through the gateway.

WRITE path:  input -> detect -> poison check -> policy -> transform -> passport -> persist
READ path:   request -> retrieval -> passport validation -> policy -> transform -> approved context
"""
import json
from db import execute, now_iso, new_id
from models import MemoryRecord


def persist_memory(
    mem_type: str, sensitivity: str, purpose: str, consent: bool, destination: str,
    ttl_days: int, payload: list[dict], policy_version: str, status: str = "ACTIVE",
) -> MemoryRecord:
    """payload: list of {field,type,value,sensitivity,action,rule_id,reason}."""
    memory_id = new_id("mem")
    payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    from passport import record_memory, create_passport
    record_memory(
        memory_id=memory_id, mem_type=mem_type, sensitivity=sensitivity,
        purpose=purpose, consent=consent, destination=destination, ttl_days=ttl_days,
        payload_json=payload_json, status=status, policy_version=policy_version,
    )
    passport = create_passport(
        memory_id=memory_id, sensitivity=sensitivity, purpose=purpose,
        consent="GRANTED" if consent else "NOT_GRANTED", destination=destination,
        ttl_days=ttl_days, payload_json=payload_json, policy_version=policy_version,
    )
    if status == "QUARANTINED":
        passport.revocation_state = "QUARANTINED"
        from passport import set_state
        set_state(memory_id, "QUARANTINED")
    return load_memory(memory_id)


def load_memory(memory_id: str) -> MemoryRecord | None:
    from passport import load_memory as _lm
    return _lm(memory_id)


def list_memories() -> list[MemoryRecord]:
    from passport import list_memories as _lm
    return _lm()


def revoke(memory_id: str, reason: str = "Revoked by user") -> MemoryRecord:
    from passport import set_state
    set_state(memory_id, "REVOKED")
    execute("UPDATE passports SET revoked_at=? WHERE memory_id=?", (now_iso(), memory_id))
    execute(
        "INSERT INTO revocations (id, memory_id, ts, reason) VALUES (?,?,?,?)",
        (new_id("rev"), memory_id, now_iso(), reason),
    )
    return load_memory(memory_id)


def reset_demo() -> int:
    """Reset memories, messages, events, receipts, revocations, traces, tokens."""
    for t in ("memories", "passports", "events", "receipts", "revocations",
              "traces", "messages", "conversations", "tokens"):
        execute(f"DELETE FROM {t}")
    execute("UPDATE meta SET value='GENESIS' WHERE key='last_receipt_hash'")
    execute("DELETE FROM meta WHERE key='request_seq'")
    return 0
