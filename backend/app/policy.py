"""MEMVERSE policy engine — versioned, typed-JSON, deterministic.

A single policy document defines:
  - rule blocks with preconditions (operation, purpose, destination, sensitivity)
  - a per-field strategy matrix (sensitivity x operation)
  - destination allow/deny lists
  - poisoning thresholds

The same input + purpose + destination + passport + policy version always
yields the same decision. Policy is stored in SQLite (policies table) and the
current version is served to the frontend via /api/policies/current.
"""
import time
import db
from models import PolicyDecision, FieldDecision, MemoryPassport

DEFAULT_POLICY = {
    "version": "v1.4",
    "name": "MEMVERSE Zero-Trust Memory Policy",
    "updated": "2026-08-01",
    "rules": [
        {
            "id": "passport.revoked",
            "if": {"passport.revocation_state": "REVOKED"},
            "then": "BLOCK",
            "reason": "Memory Passport is revoked. Retrieval fails closed.",
        },
        {
            "id": "passport.quarantined",
            "if": {"passport.revocation_state": "QUARANTINED"},
            "then": "BLOCK",
            "reason": "Memory is quarantined due to detected poisoning. It may never enter model context.",
        },
        {
            "id": "passport.expired",
            "if": {"passport.expired": True},
            "then": "BLOCK",
            "reason": "Memory Passport expired (TTL reached). Retrieval fails closed.",
        },
        {
            "id": "consent.missing",
            "if": {"passport.consent": "NOT_GRANTED"},
            "then": "BLOCK",
            "reason": "Consent not granted for this memory purpose.",
        },
        {
            "id": "destination.denied",
            "if": {"destination.allowlist": False},
            "then": "BLOCK",
            "reason": "Destination is not on the approved allowlist for this purpose.",
        },
        {
            "id": "poisoning.critical",
            "if": {"poisoning.level": "CRITICAL"},
            "then": "BLOCK",
            "reason": "Input scored CRITICAL on the poisoning detector. Request blocked, fail closed.",
        },
        {
            "id": "poisoning.high",
            "if": {"poisoning.level": "HIGH"},
            "then": "QUARANTINE",
            "reason": "Input contains instructions attempting to override agent policy. Quarantined.",
        },
        {
            "id": "operation.learn",
            "if": {"operation": "LEARN"},
            "then": "BLOCK",
            "reason": "LEARN (training/analytics reuse) is an extension path in this prototype — no data is reused for learning.",
        },
        {
            "id": "purpose.unapproved",
            "if": {"purpose.approved": False},
            "then": "BLOCK",
            "reason": "Purpose is not in the approved-purpose registry.",
        },
        {
            "id": "policy.fail_closed",
            "if": {"gateway.error": True},
            "then": "BLOCK",
            "reason": "Policy evaluation could not complete — system fails closed.",
        },
    ],
    "purpose_matrix": {
        # sensitivity -> purpose action for REVEAL
        "REVEAL": {
            "LOW": "ALLOW",
            "MEDIUM": "TRANSFORM",
            "HIGH": "TRANSFORM",
            "CRITICAL": "BLOCK",
        },
        "REMEMBER": {
            "LOW": "ALLOW",
            "MEDIUM": "TRANSFORM",
            "HIGH": "TRANSFORM",
            "CRITICAL": "BLOCK",
        },
        "LEARN": {"*": "BLOCK"},
    },
    "field_strategy": {
        # type -> {purpose_action: field action}
        "identity": {"TRANSFORM": "SUPPRESS", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "name": {"TRANSFORM": "SUPPRESS", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "contact": {"TRANSFORM": "REDACT", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "email": {"TRANSFORM": "REDACT", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "phone": {"TRANSFORM": "REDACT", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "demographic": {"TRANSFORM": "GENERALIZE", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "age": {"TRANSFORM": "GENERALIZE", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "location": {"TRANSFORM": "GENERALIZE", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "city": {"TRANSFORM": "GENERALIZE", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "education": {"TRANSFORM": "GENERALIZE", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "health": {"TRANSFORM": "REDACT", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "financial": {"TRANSFORM": "REDACT", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "credential": {"TRANSFORM": "BLOCK", "ALLOW": "BLOCK", "BLOCK": "BLOCK"},
        "task": {"TRANSFORM": "ALLOW", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
        "context": {"TRANSFORM": "ALLOW", "ALLOW": "ALLOW", "BLOCK": "BLOCK"},
    },
    "destinations": {
        "allow": ["nvidia", "nvidia_llm", "local", "assistant_context"],
        "deny": ["external", "third_party_tool", "unregistered"],
    },
    "purposes": {
        "approved": [
            "answer_query", "personalization", "task_execution", "context",
            "assistance", "chat",
        ],
        "blocked": ["training", "analytics", "advertising", "third_party_sharing"],
    },
    "poisoning_thresholds": {"quarantine": 50, "block": 80},
    "ttl_default_days": {"LOW": 30, "MEDIUM": 14, "HIGH": 7, "CRITICAL": 0},
}

PURPOSE_LABELS = {
    "answer_query": "Answer user query",
    "personalization": "Personalization",
    "task_execution": "Task execution",
    "context": "Assistant context",
    "assistance": "Assistance",
    "chat": "Chat assistance",
}


class PolicyEngine:
    def __init__(self):
        self._policy = None

    def load(self, policy: dict | None = None) -> dict:
        self._policy = policy or DEFAULT_POLICY
        return self._policy

    @property
    def policy(self) -> dict:
        if self._policy is None:
            self.load()
        return self._policy

    def version(self) -> str:
        return self.policy["version"]

    # ------------------------------------------------------------- evaluate
    def evaluate(
        self,
        operation: str,
        purpose: str,
        destination: str,
        passport: MemoryPassport | None,
        poisoning_level: str,
        entities: list,
        gateway_error: bool = False,
        consent: str | None = None,
    ) -> PolicyDecision:
        t0 = time.perf_counter()
        p = self.policy
        matched: list[dict] = []
        reason = ""
        overall = "ALLOW"

        def _state() -> dict:
            return {
                "passport.revocation_state": passport.revocation_state if passport else "NONE",
                "passport.expired": bool(passport and passport.revocation_state == "EXPIRED"),
                # no passport yet (write path): consent comes from the request
                "passport.consent": (passport.consent if passport else
                                     (consent if consent is not None else "GRANTED")),
                "destination.allowlist": (destination.lower() in p["destinations"]["allow"]),
                "poisoning.level": poisoning_level,
                "operation": operation,
                "purpose.approved": purpose in p["purposes"]["approved"],
                "gateway.error": gateway_error,
            }

        state = _state()
        for rule in p["rules"]:
            cond = rule["if"]
            hit = True
            for k, v in cond.items():
                if state.get(k) != v:
                    hit = False
                    break
            if hit:
                matched.append({"rule_id": rule["id"], "then": rule["then"], "reason": rule["reason"]})

        # highest-priority matched rule decides (document order = priority)
        if matched:
            rule = matched[0]
            overall = rule["then"]
            reason = rule["reason"]
        else:
            reason = "No blocking precondition matched."

        # per-field strategy from matrix
        per_field: list[FieldDecision] = []
        field_reasons = {
            "identity": "Identity is not required for the requested purpose.",
            "name": "Identity is not required for the requested purpose.",
            "contact": "Contact details are not required for the requested purpose.",
            "email": "Contact details are not required for the requested purpose.",
            "phone": "Contact details are not required for the requested purpose.",
            "demographic": "Exact demographic value is unnecessary; a coarser value suffices.",
            "age": "Exact age is unnecessary; an age band suffices.",
            "location": "Exact location is unnecessary; a region suffices.",
            "city": "Exact location is unnecessary; a region suffices.",
            "education": "Exact education detail is unnecessary; a band suffices.",
            "health": "Health information is not required for this purpose.",
            "financial": "Financial information is not required for this purpose.",
            "credential": "Credentials must never leave the trusted boundary.",
            "task": "Task information is required for the requested purpose.",
        }

        if overall == "BLOCK":
            for e in entities:
                per_field.append(FieldDecision(
                    field=e.entity, type=e.type, sensitivity=e.sensitivity,
                    raw_value=e.value, action="BLOCK", reason="Request blocked by policy.",
                    rule_id=matched[0]["rule_id"] if matched else "block",
                    output="",
                ))
        else:
            matrix = p["purpose_matrix"].get(operation, {})
            for e in entities:
                strat = p["field_strategy"].get(e.type)
                if strat is None:
                    act, why = "ALLOW", "No policy rule for this field type."
                    rule_id = "default.allow"
                else:
                    purpose_action = matrix.get(e.sensitivity, matrix.get("*", "TRANSFORM"))
                    if purpose_action == "BLOCK":
                        act = "BLOCK"
                        why = "Sensitivity is not permitted for this purpose at all."
                        rule_id = f"matrix.{operation}.{e.sensitivity}.block"
                    else:
                        act = strat.get(purpose_action, "ALLOW")
                        why = field_reasons.get(e.type, "Field-level policy applied.")
                        rule_id = f"matrix.{operation}.{e.sensitivity}.{act.lower()}"
                per_field.append(FieldDecision(
                    field=e.entity, type=e.type, sensitivity=e.sensitivity,
                    raw_value=e.value, action=act, reason=why,
                    rule_id=rule_id, output="",
                ))

        # if overall still ALLOW but any field is transformed => TRANSFORM
        if overall == "ALLOW" and any(f.action != "ALLOW" for f in per_field):
            overall = "TRANSFORM"
            reason = "Some fields were transformed before release; identity and precision reduced."

        return PolicyDecision(
            overall=overall,
            reason=reason,
            policy_version=self.version(),
            matched_rules=matched,
            per_field=per_field,
            ms=(time.perf_counter() - t0) * 1000,
            timestamp=db.now_iso(),
        )


# singleton
ENGINE = PolicyEngine()
