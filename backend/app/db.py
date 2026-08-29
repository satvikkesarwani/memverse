"""SQLite persistence layer for MEMVERSE.

All raw sensitive payloads are stored separately from metadata. Payloads are
stored only in the local database (never sent anywhere) — this is the
"local-only handling" boundary of the prototype.
"""
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.environ.get(
    "MEMVERSE_DB",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "memverse.db"),
)

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    created_at TEXT,
    num INTEGER
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT,
    role TEXT,
    content TEXT,
    ts TEXT,
    trace_id TEXT,
    receipt_id TEXT,
    provider TEXT
);
CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    mem_type TEXT,
    sensitivity TEXT,
    purpose TEXT,
    consent INTEGER,
    destination TEXT,
    ttl_days INTEGER,
    created_at TEXT,
    expires_at TEXT,
    passport_id TEXT,
    status TEXT,
    payload_json TEXT,
    integrity_hash TEXT,
    policy_version TEXT,
    last_access TEXT
);
CREATE TABLE IF NOT EXISTS passports (
    memory_id TEXT PRIMARY KEY,
    sensitivity TEXT,
    purpose TEXT,
    consent INTEGER,
    destination TEXT,
    ttl_days INTEGER,
    created_at TEXT,
    expires_at TEXT,
    integrity_hash TEXT,
    policy_version TEXT,
    revocation_state TEXT,
    revoked_at TEXT,
    quarantined_at TEXT
);
CREATE TABLE IF NOT EXISTS tokens (
    token_id TEXT PRIMARY KEY,
    raw_value TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    event_type TEXT,
    ts TEXT,
    decision TEXT,
    policy_version TEXT,
    memory_id TEXT,
    destination TEXT,
    receipt_id TEXT,
    latency_ms INTEGER,
    extra TEXT
);
CREATE TABLE IF NOT EXISTS receipts (
    id TEXT PRIMARY KEY,
    event_type TEXT,
    ts TEXT,
    decision TEXT,
    policy_version TEXT,
    memory_id TEXT,
    destination TEXT,
    previous_event_hash TEXT,
    event_hash TEXT,
    data_json TEXT
);
CREATE TABLE IF NOT EXISTS revocations (
    id TEXT PRIMARY KEY,
    memory_id TEXT,
    ts TEXT,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS traces (
    id TEXT PRIMARY KEY,
    message_id TEXT,
    data_json TEXT
);
CREATE TABLE IF NOT EXISTS policies (
    version TEXT PRIMARY KEY,
    data_json TEXT,
    created_at TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _lock:
        conn = get_conn()
        try:
            conn.executescript(SCHEMA)
            row = conn.execute("SELECT value FROM meta WHERE key='last_receipt_hash'").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('last_receipt_hash', ?)",
                    ("GENESIS",),
                )
            conn.commit()
        finally:
            conn.close()


def q(sql: str, params: tuple = ()) -> list[dict]:
    """Run a query and return list of dicts."""
    with _lock:
        conn = get_conn()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def execute(sql: str, params: tuple = ()) -> int:
    """Run a write statement; returns lastrowid."""
    with _lock:
        conn = get_conn()
        try:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.lastrowid or 0
        finally:
            conn.close()


def executemany(sql: str, rows: list) -> None:
    with _lock:
        conn = get_conn()
        try:
            conn.executemany(sql, rows)
            conn.commit()
        finally:
            conn.close()


def get_meta(key: str, default: str | None = None) -> str | None:
    rows = q("SELECT value FROM meta WHERE key=?", (key,))
    return rows[0]["value"] if rows else default


def set_meta(key: str, value: str) -> None:
    execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def json_dump(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
