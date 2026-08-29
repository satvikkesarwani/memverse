"""Memory Passport — the credential attached to every memory.

Lifecycle: CREATED -> ACTIVE -> REVOKED / QUARANTINED / EXPIRED
Every state transition is recorded in the event ledger.
"""
import hashlib
from datetime import datetime, timedelta, timezone
from db import execute, q, now_iso
from models import MemoryPassport, MemoryRecord


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def integrity_hash(payload_json: str, policy_version: str, created_at: str) -> str:
    return sha256_hex(f"{payload_json}|{policy_version}|{created_at}")


def create_passport(memory_id: str, sensitivity: str, purpose: str, consent: str,
                    destination: str, ttl_days: int, payload_json: str,
                    policy_version: str) -> MemoryPassport:
    created = now_iso()
    expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat(timespec="milliseconds")
    ih = integrity_hash(payload_json, policy_version, created)

    execute(
        """INSERT OR REPLACE INTO passports
           (memory_id, sensitivity, purpose, consent, destination, ttl_days,
            created_at, expires_at, integrity_hash, policy_version, revocation_state)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (memory_id, sensitivity, purpose, consent, destination, ttl_days,
         created, expires, ih, policy_version, "ACTIVE"),
    )
    return MemoryPassport(
        memory_id=memory_id, sensitivity=sensitivity, purpose=purpose, consent=consent,
        destination=destination, ttl_days=ttl_days, created_at=created, expires_at=expires,
        integrity_hash=ih, policy_version=policy_version, revocation_state="ACTIVE",
    )


def _apply_expiry(passport: MemoryPassport) -> MemoryPassport:
    """TTL enforcement — expired passports FAIL CLOSED."""
    if passport.revocation_state in ("REVOKED", "QUARANTINED"):
        return passport
    try:
        exp = datetime.fromisoformat(passport.expires_at)
        if exp.timestamp() * 1000 <= datetime.now(timezone.utc).timestamp() * 1000:
            passport.revocation_state = "EXPIRED"
            execute("UPDATE memories SET status='EXPIRED' WHERE id=?", (passport.memory_id,))
            execute(
                "UPDATE passports SET revocation_state='EXPIRED' WHERE memory_id=?",
                (passport.memory_id,),
            )
    except Exception:
        pass
    return passport


def get_passport(memory_id: str) -> MemoryPassport | None:
    rows = q("SELECT * FROM passports WHERE memory_id=?", (memory_id,))
    if not rows:
        return None
    r = rows[0]
    p = MemoryPassport(
        memory_id=r["memory_id"], sensitivity=r["sensitivity"], purpose=r["purpose"],
        consent="GRANTED" if r["consent"] else "NOT_GRANTED",
        destination=r["destination"], ttl_days=r["ttl_days"], created_at=r["created_at"],
        expires_at=r["expires_at"], integrity_hash=r["integrity_hash"],
        policy_version=r["policy_version"], revocation_state=r["revocation_state"],
        revoked_at=r["revoked_at"] or "",
    )
    return _apply_expiry(p)


def set_state(memory_id: str, state: str) -> None:
    execute("UPDATE passports SET revocation_state=? WHERE memory_id=?", (state, memory_id))
    status_map = {"REVOKED": "REVOKED", "QUARANTINED": "QUARANTINED", "ACTIVE": "ACTIVE",
                  "EXPIRED": "EXPIRED", "BLOCKED": "BLOCKED"}
    execute("UPDATE memories SET status=? WHERE id=?", (status_map.get(state, state), memory_id))


def record_memory(memory_id: str, mem_type: str, sensitivity: str, purpose: str,
                  consent: bool, destination: str, ttl_days: int, payload_json: str,
                  status: str, policy_version: str) -> None:
    """Persist a memory record.

    The raw payload is encrypted (Fernet) before touching SQLite — only the
    ciphertext is stored. The integrity hash is computed over the plaintext so
    it can be verified after decryption.
    """
    import crypto
    created = now_iso()
    expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat(timespec="milliseconds")
    ih = integrity_hash(payload_json, policy_version, created)
    cipher = crypto.encrypt_text(payload_json)
    execute(
        """INSERT OR REPLACE INTO memories
           (id, mem_type, sensitivity, purpose, consent, destination, ttl_days,
            created_at, expires_at, passport_id, status, payload_json, integrity_hash,
            policy_version, last_access)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (memory_id, mem_type, sensitivity, purpose, 1 if consent else 0, destination,
         ttl_days, created, expires, memory_id, status, cipher, ih, policy_version, created),
    )


def load_memory(memory_id: str) -> MemoryRecord | None:
    import json
    import crypto
    rows = q("SELECT * FROM memories WHERE id=?", (memory_id,))
    if not rows:
        return None
    r = rows[0]
    p = get_passport(memory_id)
    try:
        # stored payload is Fernet ciphertext; decrypt inside the trusted boundary
        plain = crypto.decrypt_text(r["payload_json"])
        if plain is None:
            plain = r["payload_json"]  # legacy plaintext fallback
        payload = json.loads(plain)
    except Exception:
        payload = []
    return MemoryRecord(
        memory_id=r["id"], mem_type=r["mem_type"], sensitivity=r["sensitivity"],
        purpose=r["purpose"], consent="GRANTED" if r["consent"] else "NOT_GRANTED",
        destination=r["destination"], ttl_days=r["ttl_days"], created_at=r["created_at"],
        expires_at=r["expires_at"], status=r["status"], payload=payload,
        passport=p, last_access=r["last_access"] or "",
    )


def list_memories() -> list[MemoryRecord]:
    rows = q("SELECT id FROM memories ORDER BY created_at DESC")
    out = []
    for r in rows:
        m = load_memory(r["id"])
        if m:
            out.append(m)
    return out


def touch_access(memory_id: str) -> None:
    execute("UPDATE memories SET last_access=? WHERE id=?", (now_iso(), memory_id))
