"""Local tokenization — deterministic, persistent mapping table (SQLite).

Used when a field's policy action is TOKENIZE. Tokens are opaque local
references; the raw value never leaves the trusted boundary.
"""
import secrets
from db import execute, q, now_iso


def tokenize(raw: str) -> str:
    v = raw.strip()
    rows = q("SELECT token_id FROM tokens WHERE raw_value=?", (v,))
    if rows:
        return rows[0]["token_id"]
    tok = "tok_" + secrets.token_hex(6)
    execute("INSERT OR REPLACE INTO tokens (token_id, raw_value, created_at) VALUES (?,?,?)",
            (tok, v, now_iso()))
    return tok


def resolve(token_id: str) -> str | None:
    rows = q("SELECT raw_value FROM tokens WHERE token_id=?", (token_id,))
    return rows[0]["raw_value"] if rows else None
