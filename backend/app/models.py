"""Strongly typed data models for MEMVERSE."""
from pydantic import BaseModel
from typing import Any


# ---------------------------------------------------------------- detection
class DetectedEntity(BaseModel):
    entity: str          # label, e.g. "Name"
    value: str           # raw value found in input
    type: str            # identity / contact / demographic / location / health / financial / credential / education / task
    sensitivity: str     # HIGH / MEDIUM / LOW
    reason: str
    confidence: float
    context: str = ""    # short surrounding text


class DetectionResult(BaseModel):
    source: str                       # "user_prompt" | "memory_payload"
    entities: list[DetectedEntity] = []
    ms: float = 0.0


# ---------------------------------------------------------------- poisoning
class PoisoningMatch(BaseModel):
    pattern: str
    weight: int
    matched_text: str


class PoisoningResult(BaseModel):
    risk_score: int = 0
    risk_level: str = "LOW"           # LOW / MEDIUM / HIGH / CRITICAL
    matched_patterns: list[PoisoningMatch] = []
    reason: str = "No suspicious patterns detected."
    action: str = "ALLOW"             # ALLOW / SANITIZE / QUARANTINE / BLOCK
    ms: float = 0.0


# ------------------------------------------------------------------- policy
class FieldDecision(BaseModel):
    field: str
    type: str
    sensitivity: str
    raw_value: str
    action: str                       # ALLOW / SUPPRESS / REDACT / GENERALIZE / TOKENIZE / BLOCK
    reason: str
    rule_id: str
    output: str = ""                  # transformed value ("" when BLOCK)


class PolicyDecision(BaseModel):
    overall: str                      # ALLOW / BLOCK / TRANSFORM / QUARANTINE / LOCAL_ONLY / REQUIRE_APPROVAL
    reason: str
    policy_version: str
    matched_rules: list[dict] = []
    per_field: list[FieldDecision] = []
    ms: float = 0.0
    timestamp: str = ""


# ----------------------------------------------------------------- passport
class MemoryPassport(BaseModel):
    memory_id: str
    sensitivity: str
    purpose: str
    consent: str                      # GRANTED / NOT_GRANTED
    destination: str
    ttl_days: int
    created_at: str
    expires_at: str
    integrity_hash: str
    policy_version: str
    revocation_state: str             # ACTIVE / REVOKED / QUARANTINED / EXPIRED
    revoked_at: str = ""


class MemoryRecord(BaseModel):
    memory_id: str
    mem_type: str
    sensitivity: str
    purpose: str
    consent: str
    destination: str
    ttl_days: int
    created_at: str
    expires_at: str
    status: str                       # ACTIVE / REVOKED / EXPIRED / QUARANTINED / BLOCKED
    payload: list[dict]               # [{field, type, value, sensitivity, action, rule_id, reason}]
    passport: MemoryPassport | None = None
    last_access: str = ""


# ------------------------------------------------------------ transformation
class ApprovedContextEntry(BaseModel):
    field: str
    type: str
    value: str
    sensitivity: str


class ApprovedContext(BaseModel):
    entries: list[ApprovedContextEntry] = []
    excluded_raw_values: list[str] = []   # raw values deliberately withheld
    excluded_raw_types: dict = {}         # raw value -> field type (for egress checks)
    assembly: str = ""                    # the exact context string handed to the model
    ms: float = 0.0


# -------------------------------------------------------------------- egress
class EgressCheck(BaseModel):
    name: str
    status: str           # PASS / FAIL
    detail: str = ""


class EgressResult(BaseModel):
    status: str           # PASS / FAIL  (FAIL => the request is BLOCKED before egress)
    checks: list[EgressCheck] = []
    prohibited_fields: int = 0
    ms: float = 0.0


# -------------------------------------------------------------------- trace
class TraceStage(BaseModel):
    id: str
    name: str
    status: str           # ok / blocked / warn / info / error
    ms: float = 0.0
    ts: str = ""          # real ISO timestamp of stage execution
    input: Any = None
    output: Any = None
    explanation: str = ""
    decision: str = ""
    fields: list = []
    policy_version: str = ""


class RequestTrace(BaseModel):
    request_id: str
    conversation_id: str = ""
    timestamp: str
    operation: str        # REMEMBER / REVEAL / LEARN / QUARANTINE_CHECK
    purpose: str
    destination: str
    prompt: str
    stages: list[TraceStage] = []
    summary: dict = {}
    request_number: int = 0    # sequential REQ-#### for judges
    session_number: int = 0    # sequential SES-#### for judges
    memverse_ms: float = 0.0   # time inside the MEMVERSE boundary (excl. model)
    model_ms: float = 0.0      # external model response time
    total_ms: float = 0.0      # end-to-end


# ------------------------------------------------------------------ receipt
class Receipt(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    purpose: str
    destination: str
    decision: str
    fields_detected: int = 0
    fields_transformed: int = 0
    policy_version: str
    passport_id: str = ""
    previous_event_hash: str
    event_hash: str
    revocation_state: str = ""
    extra: dict = {}
    verified: bool | None = None       # set by /verify


# ---------------------------------------------------------------------- LLM
class LLMMessage(BaseModel):
    role: str
    content: str


class LLMRequest(BaseModel):
    messages: list[LLMMessage]
    destination: str
    purpose: str
    provider: str = ""
    model: str = ""


class LLMResponse(BaseModel):
    text: str
    provider: str
    model: str
    latency_ms: float
    demo: bool = False
    error: str = ""


# ------------------------------------------------------------------- results
class ChatResult(BaseModel):
    message_id: str
    conversation_id: str
    user_message_id: str = ""
    response_text: str
    provider: str
    model: str
    demo: bool
    trace: RequestTrace
    receipt: Receipt
    model_input: dict = {}
    model_output: str = ""
    blocked: bool = False


class MemoryWriteResult(BaseModel):
    memory: MemoryRecord | None  # None when the write is BLOCKED (fail closed)
    trace: RequestTrace
    receipt: Receipt


class RevokeResult(BaseModel):
    memory: MemoryRecord
    receipt: Receipt
