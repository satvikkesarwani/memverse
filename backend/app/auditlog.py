"""Structured MEMVERSE audit logging.

Every pipeline stage emits a structured event carrying the SAME request_id /
request number that appears in the frontend trace, the receipts ledger, and
the NVIDIA transaction — one coherent transaction across all surfaces.

Log lines are key=value pairs (grep-able), never JSON dumps of secrets.
Raw user prompts / sensitive values are NEVER logged — only counts, types,
decisions and durations. A redacted ring buffer is exposed for judges via
GET /api/audit/logs.
"""
import logging
import threading
from collections import deque
from datetime import datetime, timezone

_RING = deque(maxlen=1000)
_LOCK = threading.Lock()

logger = logging.getLogger("memverse")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    logger.addHandler(_h)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def log_event(level: str, event: str, request_id: str = "", request_number: int = 0,
              session_id: str = "", session_number: int = 0, stage: str = "",
              status: str = "", duration_ms: float = 0.0, **meta) -> None:
    entry = {
        "ts": _now(), "level": level.upper(), "event": event,
        "request_id": request_id, "request_number": request_number,
        "session_id": session_id, "session_number": session_number,
        "stage": stage, "status": status,
        "duration_ms": round(duration_ms, 2) if duration_ms else 0,
    }
    for k, v in meta.items():
        entry[k] = v

    with _LOCK:
        _RING.append(entry)

    parts = [f"{k}={v}" for k, v in entry.items() if v not in ("", 0, None)]
    logger.log(getattr(logging, level.upper(), logging.INFO), " ".join(parts))


def recent(limit: int = 100) -> list[dict]:
    with _LOCK:
        return list(_RING)[-limit:]


# ------------------------------------------------------------------ events
def request_received(req_id, req_num, ses_id, ses_num, operation, input_length):
    log_event("INFO", "REQUEST_RECEIVED", req_id, req_num, ses_id, ses_num,
              stage="request", status="ok", operation=operation, input_length=input_length)


def memory_retrieved(req_id, req_num, ses_id, ses_num, eligible, denied, ms):
    log_event("INFO", "MEMORY_RETRIEVED", req_id, req_num, ses_id, ses_num,
              stage="memory", status="ok" if eligible else ("denied" if denied else "empty"),
              duration_ms=ms, eligible=eligible, denied=denied)


def sensitive_detected(req_id, req_num, ses_id, ses_num, count, types, ms):
    log_event("INFO", "SENSITIVE_DATA_DETECTED", req_id, req_num, ses_id, ses_num,
              stage="detect", status="ok", duration_ms=ms, count=count, types=",".join(types))


def poisoning_scored(req_id, req_num, ses_id, ses_num, level, score, ms):
    log_event("INFO", "POISONING_DEFENSE", req_id, req_num, ses_id, ses_num,
              stage="defend", status=level.lower(), duration_ms=ms, risk_level=level, risk_score=score)


def policy_evaluated(req_id, req_num, ses_id, ses_num, decision, policy_version, rules, ms):
    log_event("INFO", "POLICY_EVALUATED", req_id, req_num, ses_id, ses_num,
              stage="policy", status=decision.lower(), duration_ms=ms,
              decision=decision, policy_version=policy_version, rules=",".join(rules))


def transformation_applied(req_id, req_num, ses_id, ses_num, fields, ms):
    log_event("INFO", "TRANSFORMATION_APPLIED", req_id, req_num, ses_id, ses_num,
              stage="transform", status="ok", duration_ms=ms, fields=fields)


def passport_event(req_id, req_num, ses_id, ses_num, action, memory_id, state, ms=0.0):
    log_event("INFO", "PASSPORT_" + action.upper(), req_id, req_num, ses_id, ses_num,
              stage="passport", status=state.lower(), duration_ms=ms, memory_id=memory_id, passport_state=state)


def payload_created(req_id, req_num, ses_id, ses_num, assembly_chars, prompt_chars):
    log_event("INFO", "MODEL_PAYLOAD_CREATED", req_id, req_num, ses_id, ses_num,
              stage="context", status="ok", assembly_chars=assembly_chars, prompt_chars=prompt_chars)


def egress_validated(req_id, req_num, ses_id, ses_num, status, prohibited, ms):
    log_event("INFO", "EGRESS_VALIDATED", req_id, req_num, ses_id, ses_num,
              stage="llm_gate", status=status.lower(), duration_ms=ms, prohibited_fields=prohibited)


def model_request_sent(req_id, req_num, ses_id, ses_num, provider, model, ms):
    log_event("INFO", "MODEL_REQUEST_SENT", req_id, req_num, ses_id, ses_num,
              stage="llm", status="sent", duration_ms=ms, provider=provider, model=model)


def model_response_received(req_id, req_num, ses_id, ses_num, provider, ms):
    log_event("INFO", "MODEL_RESPONSE_RECEIVED", req_id, req_num, ses_id, ses_num,
              stage="response", status="ok", duration_ms=ms, provider=provider)


def model_request_failed(req_id, req_num, ses_id, ses_num, error_category):
    log_event("ERROR", "MODEL_REQUEST_FAILED", req_id, req_num, ses_id, ses_num,
              stage="llm", status="failed", error_category=error_category)


def request_blocked(req_id, req_num, ses_id, ses_num, reason):
    log_event("WARN", "REQUEST_BLOCKED", req_id, req_num, ses_id, ses_num,
              stage="policy", status="blocked", reason=reason)


def request_failed(req_id, req_num, ses_id, ses_num, error_category, stage=""):
    log_event("ERROR", "REQUEST_FAILED", req_id, req_num, ses_id, ses_num,
              stage=stage or "gateway", status="failed", error_category=error_category)


def receipt_created(req_id, req_num, ses_id, ses_num, receipt_id, event_type, decision):
    log_event("INFO", "SECURITY_RECEIPT_CREATED", req_id, req_num, ses_id, ses_num,
              stage="receipt", status="ok", receipt_id=receipt_id, event_type=event_type, decision=decision)


def memory_write(req_id, req_num, memory_id, decision, status, ms):
    log_event("INFO", "MEMORY_WRITE", req_id, req_num, stage="write",
              status=status.lower(), duration_ms=ms, memory_id=memory_id, decision=decision)


def memory_revoke(req_id, req_num, memory_id, state):
    log_event("WARN", "MEMORY_REVOKED", req_id, req_num, stage="revoke",
              status="revoked", memory_id=memory_id, passport_state=state)


def demo_reset():
    log_event("INFO", "DEMO_RESET", stage="demo", status="ok")
