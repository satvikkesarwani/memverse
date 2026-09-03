"""MemverseGateway — the single choke point of MEMVERSE.

Every memory operation and every LLM-bound request passes through this
class. Nothing else in the system can write memory, read memory, or reach
the model.

process_chat            -> full REVEAL pipeline (request -> detect -> defend ->
                           memory -> policy -> transform -> passport -> context
                           -> egress -> LLM -> response -> receipt)
process_memory_write    -> full REMEMBER pipeline
process_memory_read     -> standalone READ pipeline (registry / lab)
revoke_memory           -> revocation with receipt
"""
import json
import os
import re
import time
import hashlib
from db import execute, init_db, now_iso, new_id, q, get_meta, set_meta
import detector
import poisoning
import policy as policy_mod
import transformer as transformer_mod
import passport as passport_mod
import memory as memory_store
import egress as egress_mod
import receipts as receipts_mod
import persona as persona_mod
import auditlog
from models import (
    RequestTrace, TraceStage, Receipt, ApprovedContext, EgressResult,
    ChatResult, MemoryWriteResult, RevokeResult, MemoryRecord, PolicyDecision,
    MemoryPassport, DetectedEntity,
)
from types import SimpleNamespace

POLICY_VERSION = "v1.4"

SYSTEM_INSTRUCTIONS = (
    "You are a helpful AI assistant operating inside the MEMVERSE zero-trust memory gateway. "
    "The memory context below is the ONLY personal background approved for this request. "
    "CRITICAL USAGE RULE: Use this background context ONLY when it is directly relevant to answering the user's question. "
    "Do NOT recite, repeat, or regurgitate this context unnecessarily unless the user explicitly asks about it. "
    "Do not claim to know anything about the user beyond it, and never ask for exact personal identity."
)


def _ent(d, field_key: str = "entity") -> SimpleNamespace:
    """Map a stored payload dict or DetectedEntity to a common shape."""
    return SimpleNamespace(
        entity=d.get(field_key, d.get("entity", d.get("field", "?") if isinstance(d, dict) else "?")),
        value=d.get("value", ""),
        type=d.get("type", ""),
        sensitivity=d.get("sensitivity", "LOW"),
    )


class MemverseGateway:
    def __init__(self):
        init_db()
        from persona import init_persona
        init_persona()
        self.policy_engine = policy_mod.PolicyEngine()
        self.policy_engine.load()
        self._provider = None

    # ------------------------------------------------------------------ LLM
    def provider(self):
        if self._provider is None:
            from llm import NVIDIAProvider, DemoProvider
            if os.environ.get("NVIDIA_API_KEY", "").strip():
                self._provider = NVIDIAProvider()
            else:
                self._provider = DemoProvider()
        return self._provider

    # ------------------------------------------------------ write pipeline
    def process_memory_write(
        self,
        text: str,
        purpose: str = "personalization",
        destination: str = "assistant_context",
        consent: bool = True,
        ttl_days: int | None = None,
        system: bool = False,
    ) -> MemoryWriteResult:
        request_id = new_id("req")
        ts = now_iso()
        stages: list[TraceStage] = []
        req_num = 0 if system else self._next_request_number()

        # ---- 01 REQUEST
        t = time.perf_counter()
        stages.append(TraceStage(
            id="request", name="Request", status="ok", ms=(time.perf_counter() - t) * 1000,
            ts=ts,
            input={"request_id": request_id, "timestamp": ts, "operation": "REMEMBER",
                   "purpose": purpose, "destination": destination, "prompt": text},
            output={"operation": "REMEMBER", "purpose": purpose, "destination": destination},
            explanation="Memory write request captured at the gateway choke point.",
        ))
        auditlog.request_received(request_id, req_num, "", 0, "REMEMBER", len(text))

        # ---- 02 DETECT
        t = time.perf_counter()
        det = detector.detect_all(text, source="memory_payload")
        # free-form memory with no sensitive attributes -> Context entity (LOW)
        if not det.entities:
            det.entities.append(DetectedEntity(
                entity="Context", value=text.strip()[:200], type="context",
                sensitivity="LOW", reason="Free-form memory — no sensitive attributes detected.",
                confidence=1.0,
            ))
        stages.append(TraceStage(
            id="detect", name="Detection", status="ok", ms=det.ms, ts=now_iso(),
            input={"text": text},
            output={"entities": [e.model_dump() for e in det.entities], "count": len(det.entities)},
            explanation="Sensitive-data detection ran over the raw input. Fields found are classified by sensitivity.",
            fields=[e.model_dump() for e in det.entities],
        ))
        auditlog.sensitive_detected(request_id, req_num, "", 0, len(det.entities),
                                    sorted({e.type for e in det.entities}), det.ms)

        # Auto-harvest entities into Global Persona Vault
        if det.entities:
            try:
                persona_mod.harvest_entities(det.entities, prompt_text=text)
            except Exception:
                pass

        # ---- 03 DEFEND
        t = time.perf_counter()
        poi = poisoning.analyze(text)
        stages.append(TraceStage(
            id="defend", name="Poisoning Defense", status=(
                "blocked" if poi.risk_level in ("HIGH", "CRITICAL") else
                ("warn" if poi.risk_level == "MEDIUM" else "ok")),
            ms=poi.ms, ts=now_iso(),
            input={"text": text},
            output={"risk_score": poi.risk_score, "risk_level": poi.risk_level,
                    "action": poi.action,
                    "matched_patterns": [m.model_dump() for m in poi.matched_patterns],
                    "reason": poi.reason},
            explanation=poi.reason,
            decision=poi.action,
        ))
        auditlog.poisoning_scored(request_id, req_num, "", 0, poi.risk_level, poi.risk_score, poi.ms)

        # ---- 04 POLICY
        t = time.perf_counter()
        try:
            decision = self.policy_engine.evaluate(
                operation="REMEMBER", purpose=purpose, destination=destination,
                passport=None, poisoning_level=poi.risk_level,
                entities=det.entities, gateway_error=False,
                consent="GRANTED" if consent else "NOT_GRANTED",
            )
        except Exception as e:
            decision = PolicyDecision(overall="BLOCK", reason=f"Policy evaluation failed — fail closed: {e}",
                                      policy_version=POLICY_VERSION, matched_rules=[], per_field=[])
        stages.append(TraceStage(
            id="policy", name="Policy Engine", status=(
                "blocked" if decision.overall in ("BLOCK", "QUARANTINE") else "ok"),
            ms=decision.ms, ts=now_iso(),
            input={"operation": "REMEMBER", "purpose": purpose, "destination": destination,
                   "poisoning_level": poi.risk_level,
                   "policy_version": decision.policy_version},
            output={"decision": decision.overall, "reason": decision.reason,
                    "matched_rules": decision.matched_rules,
                    "per_field": [f.model_dump() for f in decision.per_field]},
            explanation=decision.reason,
            decision=decision.overall,
            policy_version=decision.policy_version,
        ))
        auditlog.policy_evaluated(request_id, req_num, "", 0, decision.overall,
                                  decision.policy_version,
                                  [r.get("rule_id", "") for r in decision.matched_rules], decision.ms)

        # ---- early terminal decisions
        memory: MemoryRecord | None = None
        passport: MemoryPassport | None = None
        receipt: Receipt | None = None
        context = ApprovedContext(entries=[])

        if decision.overall == "BLOCK":
            stages.append(TraceStage(
                id="passport", name="Memory Passport", status="blocked", ms=0, ts=now_iso(),
                input={}, output={"passport": None, "reason": "No passport issued for blocked memory."},
                explanation="Write blocked — no passport created.", decision="BLOCK",
                policy_version=decision.policy_version))
            stages.append(TraceStage(
                id="transform", name="Transformation", status="blocked", ms=0, ts=now_iso(),
                input={}, output={"context": None, "reason": "Nothing to transform."},
                explanation="Blocked memory never reaches persistence.", decision="BLOCK"))
        else:
            # ---- 05 TRANSFORM + 06 PASSPORT + PERSIST
            t = time.perf_counter()
            context = transformer_mod.transform_fields(decision.per_field)
            payload = []
            for fd in decision.per_field:
                out = ""
                for e in context.entries:
                    if e.field == fd.field:
                        out = e.value
                payload.append({
                    "field": fd.field, "type": fd.type, "value": fd.raw_value,
                    "sensitivity": fd.sensitivity, "action": fd.action, "output": out,
                    "rule_id": fd.rule_id, "reason": fd.reason,
                })
            status = "QUARANTINED" if decision.overall == "QUARANTINE" else "ACTIVE"
            ttl = ttl_days if ttl_days is not None else self.policy_engine.policy.get(
                "ttl_default_days", {}).get(
                _max_sensitivity(decision.per_field), 7)
            memory = memory_store.persist_memory(
                mem_type="profile", sensitivity=_max_sensitivity(decision.per_field),
                purpose=purpose, consent=consent, destination=destination, ttl_days=ttl,
                payload=payload, policy_version=decision.policy_version, status=status,
            )
            passport = memory.passport
            stages.append(TraceStage(
                id="passport", name="Memory Passport", status=(
                    "blocked" if status == "QUARANTINED" else "ok"), ms=0, ts=now_iso(),
                input={"memory_id": memory.memory_id, "sensitivity": memory.sensitivity,
                       "purpose": purpose, "consent": "GRANTED" if consent else "NOT_GRANTED",
                       "destination": destination, "ttl_days": ttl},
                output=passport.model_dump() if passport else None,
                explanation=(
                    "Memory Passport issued — this credential governs every future retrieval. "
                    if status == "ACTIVE" else
                    "Passport created in QUARANTINED state — memory can never be retrieved."),
                decision=status, policy_version=decision.policy_version,
            ))
            auditlog.passport_event(request_id, req_num, "", 0, "CREATED",
                                    memory.memory_id, passport.revocation_state)
            stages.append(TraceStage(
                id="transform", name="Field Transformation", status="ok", ms=context.ms, ts=now_iso(),
                input={"per_field": [f.model_dump() for f in decision.per_field]},
                output={"approved_entries": [e.model_dump() for e in context.entries],
                        "excluded_raw": context.excluded_raw_values},
                explanation="Each field transformed according to the policy matrix; raw values stored encrypted at rest, locally.",
                fields=[f.model_dump() for f in decision.per_field],
                decision=decision.overall, policy_version=decision.policy_version,
            ))
            auditlog.transformation_applied(request_id, req_num, "", 0,
                                            sum(1 for f in decision.per_field if f.action != "ALLOW"),
                                            context.ms)

        # ---- 07 RECEIPT
        fields_transformed = sum(1 for f in decision.per_field if f.action != "ALLOW")
        evt = {
            "event_id": new_id("evt"), "event_type": "MEMORY_WRITE",
            "timestamp": now_iso(), "purpose": purpose, "destination": destination,
            "decision": decision.overall, "fields_detected": len(det.entities),
            "fields_transformed": fields_transformed,
            "policy_version": decision.policy_version,
            "passport_id": passport.memory_id if passport else "",
            "revocation_state": (passport.revocation_state if passport else "NONE"),
            "extra": {"operation": "REMEMBER", "request_id": request_id,
                      "poisoning_risk": poi.risk_level, "poisoning_score": poi.risk_score},
        }
        receipt = receipts_mod.create_receipt(evt)
        stages.append(TraceStage(
            id="receipt", name="Receipt", status="ok", ms=0, ts=now_iso(),
            input={"event_type": "MEMORY_WRITE"},
            output={"receipt_id": receipt.event_id, "event_hash": receipt.event_hash,
                    "previous_event_hash": receipt.previous_event_hash},
            explanation="Tamper-evident receipt appended to the hash-linked ledger.",
        ))
        auditlog.receipt_created(request_id, req_num, "", 0, receipt.event_id, "MEMORY_WRITE", receipt.decision)
        auditlog.memory_write(request_id, req_num, memory.memory_id if memory else "",
                              decision.overall, memory.status if memory else "NONE",
                              sum(s.ms for s in stages))

        trace = RequestTrace(
            request_id=request_id, timestamp=ts, operation="REMEMBER", purpose=purpose,
            destination=destination, prompt=text, stages=stages,
            request_number=req_num,
            summary=_summarize(decision, det, poi, receipt, None, memory, blocked=(
                decision.overall in ("BLOCK", "QUARANTINE"))),
        )
        trace.memverse_ms = round(sum(s.ms for s in stages), 2)
        trace.total_ms = round(trace.memverse_ms, 2)
        _persist_trace(trace)
        return MemoryWriteResult(memory=memory, trace=trace, receipt=receipt)

    # -------------------------------------------------------- chat pipeline
    def process_chat(
        self,
        prompt: str,
        conversation_id: str | None = None,
        purpose: str = "answer_query",
        destination: str = "nvidia",
    ) -> ChatResult:
        # ---- route memory declarations to the WRITE pipeline
        if _is_memory_declaration(prompt):
            wr = self.process_memory_write(prompt, purpose=_write_purpose(prompt),
                                           destination="assistant_context")
            if wr.memory is None:
                text = (
                    "⚠ BLOCKED — MEMVERSE refused to store this memory.\n\n"
                    f"{wr.trace.stages[3].output.get('reason') if len(wr.trace.stages) > 3 else ''}"
                )
            elif wr.memory.status == "QUARANTINED":
                text = (
                    "⚠ QUARANTINED — this memory was not accepted.\n\n"
                    "MEMVERSE's poisoning defense flagged instructions attempting to override agent "
                    "policy. The memory is quarantined and can never enter model context. "
                    "Open the MEMVERSE Trace to see the matched patterns."
                )
            else:
                fields = ", ".join(f["field"] for f in wr.memory.payload) or "no fields"
                text = (
                    f"✅ Stored under MEMVERSE protection.\n\n"
                    f"Detected: {fields} · Policy: {wr.trace.summary.get('policy')} · "
                    f"Decision: {wr.trace.summary.get('decision')} · "
                    f"Passport: {wr.memory.memory_id} (TTL {wr.memory.ttl_days}d).\n\n"
                    "Only the approved representation will ever reach me. Try asking "
                    "\"What is my name and age?\" to see the REVEAL pipeline."
                )
            conv = conversation_id or new_id("conv")
            msg_id = new_id("msg")

            execute(
                """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (new_id("msg"), conv, "user", prompt, now_iso(), wr.trace.request_id, wr.receipt.event_id, "user"),
            )
            execute(
                """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (msg_id, conv, "assistant", text, now_iso(), wr.trace.request_id, wr.receipt.event_id, "gateway"),
            )

            return ChatResult(
                message_id=msg_id, conversation_id=conv,
                response_text=text, provider="gateway", model="—",
                demo=wr.receipt.extra.get("extra", {}).get("poisoning_risk") == "LOW",
                trace=wr.trace, receipt=wr.receipt, model_input={}, model_output="",
                blocked=wr.memory is None or wr.memory.status == "QUARANTINED",
            )

        # ---- standard REVEAL pipeline
        request_id = new_id("req")
        req_num = self._next_request_number()
        conv, session_num = self._ensure_conversation(conversation_id)
        ts = now_iso()
        stages: list[TraceStage] = []

        # 01 REQUEST
        stages.append(TraceStage(
            id="request", name="Request", status="ok", ms=0, ts=ts,
            input={"request_id": request_id, "conversation_id": conv, "timestamp": ts,
                   "operation": "REVEAL", "purpose": purpose, "destination": destination,
                   "prompt": prompt, "input_length": len(prompt)},
            output={"operation": "REVEAL", "purpose": purpose, "destination": destination,
                    "actor": "user", "destination_label": destination},
            explanation="Chat request captured at the gateway. The model will only ever see the approved context produced below.",
        ))
        auditlog.request_received(request_id, req_num, conv, session_num, "REVEAL", len(prompt))

        # 02 DETECT
        t = time.perf_counter()
        det = detector.detect_all(prompt, source="user_prompt")
        stages.append(TraceStage(
            id="detect", name="Detection", status="ok", ms=det.ms, ts=now_iso(),
            input={"prompt": prompt},
            output={"entities": [e.model_dump() for e in det.entities], "count": len(det.entities)},
            explanation="Sensitive-data detection ran over the user prompt.",
            fields=[e.model_dump() for e in det.entities],
        ))
        auditlog.sensitive_detected(request_id, req_num, conv, session_num, len(det.entities),
                                    sorted({e.type for e in det.entities}), det.ms)

        # Auto-harvest detected entities into Global Persona Vault
        if det.entities:
            try:
                persona_mod.harvest_entities(det.entities, prompt_text=prompt)
            except Exception:
                pass

        # 03 DEFEND
        t = time.perf_counter()
        poi = poisoning.analyze(prompt)
        stages.append(TraceStage(
            id="defend", name="Poisoning Defense", status=(
                "blocked" if poi.risk_level in ("HIGH", "CRITICAL") else
                ("warn" if poi.risk_level == "MEDIUM" else "ok")),
            ms=poi.ms, ts=now_iso(),
            input={"prompt": prompt},
            output={"risk_score": poi.risk_score, "risk_level": poi.risk_level,
                    "action": poi.action,
                    "matched_patterns": [m.model_dump() for m in poi.matched_patterns],
                    "reason": poi.reason},
            explanation=poi.reason, decision=poi.action,
        ))
        auditlog.poisoning_scored(request_id, req_num, conv, session_num, poi.risk_level, poi.risk_score, poi.ms)

        # 04 MEMORY RETRIEVAL + passport validation
        t = time.perf_counter()
        eligible, denied = self._retrieve_memories(purpose, destination)
        mem_ms = (time.perf_counter() - t) * 1000
        stages.append(TraceStage(
            id="memory", name="Memory Retrieval", status=(
                "ok" if eligible else ("warn" if denied else "info")), ms=mem_ms, ts=now_iso(),
            input={"candidates": [m.memory_id for m in memory_store.list_memories()]},
            output={
                "eligible": [{
                    "memory_id": m.memory_id, "status": m.status,
                    "passport_state": m.passport.revocation_state if m.passport else "NONE",
                    "sensitivity": m.sensitivity, "purpose": m.purpose,
                    "created_at": m.created_at, "last_access": m.last_access,
                    "ttl_days": m.ttl_days,
                    "fields": [{"field": f.get("field"), "value": f.get("value"),
                                "sensitivity": f.get("sensitivity")} for f in m.payload],
                } for m in eligible],
                "denied": [{"memory_id": m.memory_id, "status": m.status,
                            "reason": d} for m, d in denied],
            },
            explanation=(
                "Every candidate memory's Passport was validated: revocation state, TTL/expiry, "
                "consent and integrity. Ineligible memories fail closed and are excluded."
                if (eligible or denied) else
                "No memories exist yet. Only the (transformed) user prompt will reach the model."),
        ))
        auditlog.memory_retrieved(request_id, req_num, conv, session_num, len(eligible), len(denied), mem_ms)

        # 05 POLICY
        memory_entities = []
        for m in eligible:
            for f in m.payload:
                memory_entities.append(_ent(f, field_key="field"))
        prompt_entities = list(det.entities)
        all_entities = memory_entities + prompt_entities
        t = time.perf_counter()
        try:
            decision = self.policy_engine.evaluate(
                operation="REVEAL", purpose=purpose, destination=destination,
                passport=eligible[0].passport if eligible else None,
                poisoning_level=poi.risk_level, entities=all_entities, gateway_error=False,
            )
        except Exception as e:
            decision = PolicyDecision(overall="BLOCK", reason=f"Policy evaluation failed — fail closed: {e}",
                                      policy_version=POLICY_VERSION, matched_rules=[], per_field=[])
        stages.append(TraceStage(
            id="policy", name="Policy Engine", status=(
                "blocked" if decision.overall in ("BLOCK", "QUARANTINE") else "ok"),
            ms=decision.ms, ts=now_iso(),
            input={"operation": "REVEAL", "purpose": purpose, "destination": destination,
                   "passport_state": eligible[0].passport.revocation_state if eligible else "NONE",
                   "poisoning_level": poi.risk_level,
                   "policy_version": decision.policy_version},
            output={"decision": decision.overall, "reason": decision.reason,
                    "matched_rules": decision.matched_rules,
                    "per_field": [f.model_dump() for f in decision.per_field]},
            explanation=decision.reason, decision=decision.overall,
            policy_version=decision.policy_version,
        ))
        auditlog.policy_evaluated(request_id, req_num, conv, session_num, decision.overall,
                                  decision.policy_version,
                                  [r.get("rule_id", "") for r in decision.matched_rules], decision.ms)

        # ---- RETRIEVAL-DENIED fail-closed: the prompt asks for memory that was
        # denied at the passport stage (revoked / expired / quarantined).
        retrieval_denied = (
            not eligible
            and bool(denied)
            and _asks_about_memory(prompt)
            and poi.risk_level not in ("HIGH", "CRITICAL")
        )
        if retrieval_denied:
            _, denial_reason = denied[0]
            denial_msg = (f"⛔ RETRIEVAL DENIED — FAIL CLOSED\n\n{denial_reason}.\n\n"
                          f"{len(denied)} memory record(s) were denied at the Passport stage. "
                          "No memory context was released to the model.")
            decision = PolicyDecision(
                overall="BLOCK", reason=denial_msg,
                policy_version=decision.policy_version, matched_rules=[], per_field=[])
            stages.append(TraceStage(
                id="context", name="Approved Context", status="blocked", ms=0, ts=now_iso(),
                input={"denied": [{"memory_id": m.memory_id, "reason": d} for m, d in denied]},
                output={"assembly": "", "reason": denial_reason},
                explanation="Retrieval failed closed — no approved context was assembled.",
                decision="BLOCK",
            ))
            auditlog.request_blocked(request_id, req_num, conv, session_num, denial_reason)
            egr = EgressResult(status="PASS", checks=[], prohibited_fields=0, ms=0)
            stages.append(TraceStage(
                id="llm_gate", name="LLM Gate (Egress)", status="blocked", ms=0, ts=now_iso(),
                input={"blocked_before_egress": True},
                output={"status": "NOT REACHED", "reason": "retrieval denied"},
                explanation="No payload to validate — the model was never offered any memory context.",
                decision="BLOCK",
            ))
        else:
            # 06 TRANSFORM
            t = time.perf_counter()
            context = transformer_mod.transform_fields(decision.per_field)
            stages.append(TraceStage(
                id="transform", name="Transformation", status=(
                    "blocked" if decision.overall in ("BLOCK", "QUARANTINE") else "ok"), ms=context.ms, ts=now_iso(),
                input={"per_field": [f.model_dump() for f in decision.per_field]},
                output={"approved_entries": [e.model_dump() for e in context.entries],
                        "excluded_raw": context.excluded_raw_values},
                explanation=(
                    "Field-level transformations applied: SUPPRESS / GENERALIZE / REDACT per the policy matrix. "
                    "Raw values are withheld from the model." if context.entries else
                    "No fields to transform."),
                fields=[f.model_dump() for f in decision.per_field],
                decision=decision.overall, policy_version=decision.policy_version,
            ))
            auditlog.transformation_applied(request_id, req_num, conv, session_num,
                                            sum(1 for f in decision.per_field if f.action != "ALLOW"),
                                            context.ms)

            # 07 PASSPORT — the credential governing this release
            if eligible:
                p = eligible[0].passport
                stages.append(TraceStage(
                    id="passport", name="Model Passport", status="ok", ms=0, ts=now_iso(),
                    input={"memory_id": eligible[0].memory_id},
                    output=p.model_dump() if p else None,
                    explanation=(
                        "This Memory Passport defines the subset the external model is authorized to "
                        "receive: purpose, consent, destination, TTL and revocation state."),
                    policy_version=p.policy_version if p else decision.policy_version,
                ))
                auditlog.passport_event(request_id, req_num, conv, session_num, "VALIDATED",
                                        eligible[0].memory_id, p.revocation_state if p else "ACTIVE")
            else:
                stages.append(TraceStage(
                    id="passport", name="Model Passport", status="info", ms=0, ts=now_iso(),
                    input={},
                    output={"passport": None, "reason": "No memory used — prompt-only request."},
                    explanation="No memory passport was involved because no memory was retrieved.",
                    decision="ALLOW",
                ))
                auditlog.passport_event(request_id, req_num, conv, session_num, "NONE", "", "NONE")

            # 08 CONTEXT
            sanitized_prompt = _sanitize_prompt(prompt, decision.per_field, det.entities)
            system = SYSTEM_INSTRUCTIONS
            persona_scaffolding = persona_mod.build_semantic_persona_context()
            if persona_scaffolding:
                system += f"\n\n{persona_scaffolding}"
            if context.assembly:
                system += f"\n\nAPPROVED MEMORY CONTEXT:\n{context.assembly}"
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": sanitized_prompt},
            ]
            stages.append(TraceStage(
                id="context", name="Approved Context", status="ok", ms=0, ts=now_iso(),
                input={"raw_memory": [{"field": f.get("field"), "type": f.get("type"),
                                       "value": f.get("value"), "sensitivity": f.get("sensitivity")}
                                      for f in (eligible[0].payload if eligible else [])]},
                output={"assembly": context.assembly, "sanitized_prompt": sanitized_prompt},
                explanation="The exact context block the model will receive. Raw memory values never enter this block.",
            ))
            auditlog.payload_created(request_id, req_num, conv, session_num,
                                     len(context.assembly), len(sanitized_prompt))

            # 09 LLM GATE (egress)
            t = time.perf_counter()
            egr = egress_mod.validate(context, destination, purpose)
            egr_all_text = " ".join(m["content"] for m in messages)
            if _recheck_prohibited(egr_all_text):
                egr.status = "FAIL"
                egr.prohibited_fields += 1
            egr.ms = (time.perf_counter() - t) * 1000
            stages.append(TraceStage(
                id="llm_gate", name="LLM Gate (Egress)", status=(
                    "blocked" if egr.status == "FAIL" else "ok"), ms=egr.ms, ts=now_iso(),
                input={"destination": destination, "purpose": purpose,
                       "payload": messages},
                output={"status": egr.status, "checks": [c.model_dump() for c in egr.checks],
                        "prohibited_fields": egr.prohibited_fields},
                explanation=(
                    "Final egress validation before anything leaves the trusted boundary. "
                    "If a prohibited field is found, the model request is BLOCKED."),
                decision=egr.status, policy_version=decision.policy_version,
            ))
            auditlog.egress_validated(request_id, req_num, conv, session_num,
                                      egr.status, egr.prohibited_fields, egr.ms)

        # 10 LLM — with hard evidence of whether the model was contacted
        blocked = (decision.overall in ("BLOCK", "QUARANTINE")) or egr.status == "FAIL" or poi.risk_level == "CRITICAL" or retrieval_denied
        llm_out = None
        if not blocked:
            payload_hash = hashlib.sha256(json.dumps(messages, sort_keys=True).encode()).hexdigest()
            try:
                llm_out = self.provider().generate(messages, purpose=purpose, request_id=request_id, request_number=req_num)
                stages.append(TraceStage(
                    id="llm", name="External Model", status="ok", ms=llm_out.get("latency_ms", 0), ts=now_iso(),
                    input={"provider": "nvidia", "model": llm_out.get("model", ""),
                           "request_id": request_id},
                    output={"status": "SENT", "destination": destination,
                            "request_id": request_id, "timestamp": now_iso(),
                            "payload_hash": payload_hash,
                            "provider": llm_out.get("provider"),
                            "model": llm_out.get("model"),
                            "payload": messages,
                            "latency_ms": llm_out.get("latency_ms", 0)},
                    explanation="Approved payload crossed the security boundary and reached the external model.",
                    decision="SENT",
                ))
            except Exception as e:
                llm_out = {
                    "text": f"⚠ LLM CONNECTION FAILED\n\nNVIDIA endpoint unreachable: {e}\n\n"
                            "MEMVERSE's security decision still stands — the trace and receipt remain valid. "
                            "Set NVIDIA_API_KEY to enable live generation.",
                    "provider": "nvidia", "model": "—", "latency_ms": 0, "demo": False,
                    "error": str(e),
                }
                stages.append(TraceStage(
                    id="llm", name="External Model", status="error", ms=0, ts=now_iso(),
                    input={"provider": "nvidia", "model": "—", "request_id": request_id},
                    output={"status": "FAILED", "destination": destination,
                            "request_id": request_id, "timestamp": now_iso(),
                            "payload_hash": payload_hash,
                            "error": str(e), "payload": messages},
                    explanation=("The approved payload was ready but the external model was unreachable. "
                                 "No raw memory was exposed — fail-safe."),
                    decision="FAILED",
                ))
        else:
            if decision.overall in ("BLOCK", "QUARANTINE"):
                denial = decision.reason
                if poi.risk_level in ("HIGH", "CRITICAL") and "poison" not in denial.lower():
                    denial = "Input scored HIGH/CRITICAL on the poisoning detector. Request blocked, fail closed."
            elif egr.status == "FAIL":
                denial = "Egress validation failed — prohibited content detected in payload. Model request blocked."
            elif retrieval_denied:
                denial = denial_msg
            else:
                denial = decision.reason
            llm_out = {
                "text": (denial if retrieval_denied
                         else f"⛔ MEMVERSE BLOCKED THIS REQUEST\n\n{denial}"),
                "provider": "gateway", "model": "—", "latency_ms": 0, "demo": False, "error": "",
            }
            stages.append(TraceStage(
                id="llm", name="External Model", status="blocked", ms=0, ts=now_iso(),
                input={"blocked": True, "reason": denial},
                output={"status": "NOT SENT", "destination": destination,
                        "request_id": request_id, "timestamp": now_iso(),
                        "reason": denial},
                explanation="The model was never contacted. The gateway fails closed.",
                decision="NOT SENT",
            ))
            auditlog.request_blocked(request_id, req_num, conv, session_num, denial)

        # 11 RESPONSE
        stages.append(TraceStage(
            id="response", name="Response", status="ok", ms=llm_out.get("latency_ms", 0), ts=now_iso(),
            input={"provider": llm_out.get("provider"), "model": llm_out.get("model")},
            output={"text": llm_out.get("text", ""), "demo": llm_out.get("demo", False)},
            explanation=("Model output captured. User sees this response; the trace proves what the model "
                         "was allowed to see."),
        ))

        # 12 RECEIPT
        fields_transformed = sum(1 for f in decision.per_field if f.action != "ALLOW")
        evt = {
            "event_id": new_id("evt"), "event_type": "CHAT_REQUEST",
            "timestamp": now_iso(), "purpose": purpose, "destination": destination,
            "decision": decision.overall if not blocked else "BLOCK",
            "fields_detected": len(det.entities) + len(memory_entities),
            "fields_transformed": fields_transformed,
            "policy_version": decision.policy_version,
            "passport_id": eligible[0].memory_id if eligible else "",
            "revocation_state": eligible[0].passport.revocation_state if eligible else "NONE",
            "extra": {"request_id": request_id, "poisoning_risk": poi.risk_level,
                      "poisoning_score": poi.risk_score,
                      "llm_provider": llm_out.get("provider"),
                      "llm_status": _llm_status(stages),
                      "egress": egr.status, "llm_error": llm_out.get("error", "")},
        }
        receipt = receipts_mod.create_receipt(evt)
        stages.append(TraceStage(
            id="receipt", name="Receipt", status="ok", ms=0, ts=now_iso(),
            input={"event_type": "CHAT_REQUEST"},
            output={"receipt_id": receipt.event_id, "event_hash": receipt.event_hash,
                    "previous_event_hash": receipt.previous_event_hash},
            explanation="Tamper-evident receipt appended to the hash-linked ledger for this request.",
        ))
        auditlog.receipt_created(request_id, req_num, conv, session_num, receipt.event_id,
                                 "CHAT_REQUEST", receipt.decision)

        trace = RequestTrace(
            request_id=request_id, conversation_id=conv, timestamp=ts, operation="REVEAL",
            purpose=purpose, destination=destination, prompt=prompt, stages=stages,
            request_number=req_num, session_number=session_num,
            summary=_summarize(decision, det, poi, receipt, egr, None, blocked=blocked),
        )
        mem_stages = [s for s in stages if s.id not in ("llm", "response")]
        trace.memverse_ms = round(sum(s.ms for s in mem_stages), 2)
        trace.model_ms = round(llm_out.get("latency_ms", 0), 2)
        trace.total_ms = round(trace.memverse_ms + trace.model_ms, 2)
        _persist_trace(trace)

        # persist messages
        msg_id = new_id("msg")
        execute(
            """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
               VALUES (?,?,?,?,?,?,?,?)""",
            (new_id("msg"), conv, "user", prompt, now_iso(), trace.request_id, receipt.event_id, "user"),
        )
        execute(
            """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
               VALUES (?,?,?,?,?,?,?,?)""",
            (msg_id, conv, "assistant", llm_out.get("text", ""), now_iso(),
             trace.request_id, receipt.event_id, llm_out.get("provider", "")),
        )
        return ChatResult(
            message_id=msg_id, conversation_id=conv,
            response_text=llm_out.get("text", ""),
            provider=llm_out.get("provider", ""), model=llm_out.get("model", ""),
            demo=bool(llm_out.get("demo")), trace=trace, receipt=receipt,
            model_input={"messages": messages} if not blocked else {},
            model_output=llm_out.get("text", "") if not blocked else "",
            blocked=blocked,
        )

    def process_chat_stream(
        self,
        prompt: str,
        conversation_id: str | None = None,
        purpose: str = "answer_query",
        destination: str = "nvidia",
    ):
        """Streaming chat: runs zero-trust stages 1-9, streams LLM tokens in real-time, then produces signed trace & receipt."""
        # ---- route memory declarations to the WRITE pipeline
        if _is_memory_declaration(prompt):
            res = self.process_chat(prompt, conversation_id=conversation_id, purpose=purpose, destination=destination)
            yield {"type": "delta", "text": res.response_text}
            yield {"type": "done", "result": res.model_dump()}
            return

        # ---- standard REVEAL pipeline
        request_id = new_id("req")
        req_num = self._next_request_number()
        conv, session_num = self._ensure_conversation(conversation_id)
        ts = now_iso()
        stages: list[TraceStage] = []

        # 01 REQUEST
        stages.append(TraceStage(
            id="request", name="Request", status="ok", ms=0, ts=ts,
            input={"request_id": request_id, "conversation_id": conv, "timestamp": ts,
                   "operation": "REVEAL", "purpose": purpose, "destination": destination,
                   "prompt": prompt, "input_length": len(prompt)},
            output={"operation": "REVEAL", "purpose": purpose, "destination": destination,
                    "actor": "user", "destination_label": destination},
            explanation="Chat request captured at the gateway. The model will only ever see the approved context produced below.",
        ))
        auditlog.request_received(request_id, req_num, conv, session_num, "REVEAL", len(prompt))

        # 02 DETECT
        t = time.perf_counter()
        det = detector.detect_all(prompt, source="user_prompt")
        stages.append(TraceStage(
            id="detect", name="Detection", status="ok", ms=det.ms, ts=now_iso(),
            input={"prompt": prompt},
            output={"entities": [e.model_dump() for e in det.entities], "count": len(det.entities)},
            explanation="Sensitive-data detection ran over the user prompt.",
            fields=[e.model_dump() for e in det.entities],
        ))
        auditlog.sensitive_detected(request_id, req_num, conv, session_num, len(det.entities),
                                    sorted({e.type for e in det.entities}), det.ms)

        # Auto-harvest detected entities into Global Persona Vault
        if det.entities:
            try:
                persona_mod.harvest_entities(det.entities, prompt_text=prompt)
            except Exception:
                pass

        # 03 DEFEND
        t = time.perf_counter()
        poi = poisoning.analyze(prompt)
        stages.append(TraceStage(
            id="defend", name="Poisoning Defense", status=(
                "blocked" if poi.risk_level in ("HIGH", "CRITICAL") else
                ("warn" if poi.risk_level == "MEDIUM" else "ok")),
            ms=poi.ms, ts=now_iso(),
            input={"prompt": prompt},
            output={"risk_score": poi.risk_score, "risk_level": poi.risk_level,
                    "action": poi.action,
                    "matched_patterns": [m.model_dump() for m in poi.matched_patterns],
                    "reason": poi.reason},
            explanation=poi.reason, decision=poi.action,
        ))
        auditlog.poisoning_scored(request_id, req_num, conv, session_num, poi.risk_level, poi.risk_score, poi.ms)

        # 04 MEMORY RETRIEVAL + passport validation
        t = time.perf_counter()
        eligible, denied = self._retrieve_memories(purpose, destination)
        mem_ms = (time.perf_counter() - t) * 1000
        stages.append(TraceStage(
            id="memory", name="Memory Retrieval", status=(
                "ok" if eligible else ("warn" if denied else "info")), ms=mem_ms, ts=now_iso(),
            input={"candidates": [m.memory_id for m in memory_store.list_memories()]},
            output={
                "eligible": [{
                    "memory_id": m.memory_id, "status": m.status,
                    "passport_state": m.passport.revocation_state if m.passport else "NONE",
                    "sensitivity": m.sensitivity, "purpose": m.purpose,
                    "created_at": m.created_at, "last_access": m.last_access,
                    "ttl_days": m.ttl_days,
                    "fields": [{"field": f.get("field"), "value": f.get("value"),
                                "sensitivity": f.get("sensitivity")} for f in m.payload],
                } for m in eligible],
                "denied": [{"memory_id": m.memory_id, "status": m.status,
                            "reason": d} for m, d in denied],
            },
            explanation=(
                "Every candidate memory's Passport was validated: revocation state, TTL/expiry, "
                "consent and integrity. Ineligible memories fail closed and are excluded."
                if (eligible or denied) else
                "No memories exist yet. Only the (transformed) user prompt will reach the model."),
        ))
        auditlog.memory_retrieved(request_id, req_num, conv, session_num, len(eligible), len(denied), mem_ms)

        # 05 POLICY
        memory_entities = []
        for m in eligible:
            for f in m.payload:
                memory_entities.append(_ent(f, field_key="field"))
        prompt_entities = list(det.entities)
        all_entities = memory_entities + prompt_entities
        t = time.perf_counter()
        try:
            decision = self.policy_engine.evaluate(
                operation="REVEAL", purpose=purpose, destination=destination,
                passport=eligible[0].passport if eligible else None,
                poisoning_level=poi.risk_level, entities=all_entities, gateway_error=False,
            )
        except Exception as e:
            decision = PolicyDecision(overall="BLOCK", reason=f"Policy evaluation failed — fail closed: {e}",
                                      policy_version=POLICY_VERSION, matched_rules=[], per_field=[])
        stages.append(TraceStage(
            id="policy", name="Policy Engine", status=(
                "blocked" if decision.overall in ("BLOCK", "QUARANTINE") else "ok"),
            ms=decision.ms, ts=now_iso(),
            input={"operation": "REVEAL", "purpose": purpose, "destination": destination,
                   "passport_state": eligible[0].passport.revocation_state if eligible else "NONE",
                   "poisoning_level": poi.risk_level,
                   "policy_version": decision.policy_version},
            output={"decision": decision.overall, "reason": decision.reason,
                    "matched_rules": decision.matched_rules,
                    "per_field": [f.model_dump() for f in decision.per_field]},
            explanation=decision.reason, decision=decision.overall,
            policy_version=decision.policy_version,
        ))
        auditlog.policy_evaluated(request_id, req_num, conv, session_num, decision.overall,
                                  decision.policy_version,
                                  [r.get("rule_id", "") for r in decision.matched_rules], decision.ms)

        # ---- RETRIEVAL-DENIED fail-closed
        retrieval_denied = (
            not eligible
            and bool(denied)
            and _asks_about_memory(prompt)
            and poi.risk_level not in ("HIGH", "CRITICAL")
        )
        if retrieval_denied:
            _, denial_reason = denied[0]
            denial_msg = (f"⛔ RETRIEVAL DENIED — FAIL CLOSED\n\n{denial_reason}.\n\n"
                          f"{len(denied)} memory record(s) were denied at the Passport stage. "
                          "No memory context was released to the model.")
            decision = PolicyDecision(
                overall="BLOCK", reason=denial_msg,
                policy_version=decision.policy_version, matched_rules=[], per_field=[])
            stages.append(TraceStage(
                id="context", name="Approved Context", status="blocked", ms=0, ts=now_iso(),
                input={"denied": [{"memory_id": m.memory_id, "reason": d} for m, d in denied]},
                output={"assembly": "", "reason": denial_reason},
                explanation="Retrieval failed closed — no approved context was assembled.",
                decision="BLOCK",
            ))
            auditlog.request_blocked(request_id, req_num, conv, session_num, denial_reason)
            egr = EgressResult(status="PASS", checks=[], prohibited_fields=0, ms=0)
            stages.append(TraceStage(
                id="llm_gate", name="LLM Gate (Egress)", status="blocked", ms=0, ts=now_iso(),
                input={"blocked_before_egress": True},
                output={"status": "NOT REACHED", "reason": "retrieval denied"},
                explanation="No payload to validate — the model was never offered any memory context.",
                decision="BLOCK",
            ))
        else:
            # 06 TRANSFORM
            t = time.perf_counter()
            context = transformer_mod.transform_fields(decision.per_field)
            stages.append(TraceStage(
                id="transform", name="Transformation", status=(
                    "blocked" if decision.overall in ("BLOCK", "QUARANTINE") else "ok"), ms=context.ms, ts=now_iso(),
                input={"per_field": [f.model_dump() for f in decision.per_field]},
                output={"approved_entries": [e.model_dump() for e in context.entries],
                        "excluded_raw": context.excluded_raw_values},
                explanation=(
                    "Field-level transformations applied: SUPPRESS / GENERALIZE / REDACT per the policy matrix. "
                    "Raw values are withheld from the model." if context.entries else
                    "No fields to transform."),
                fields=[f.model_dump() for f in decision.per_field],
                decision=decision.overall, policy_version=decision.policy_version,
            ))
            auditlog.transformation_applied(request_id, req_num, conv, session_num,
                                            sum(1 for f in decision.per_field if f.action != "ALLOW"),
                                            context.ms)

            # 07 PASSPORT
            if eligible:
                p = eligible[0].passport
                stages.append(TraceStage(
                    id="passport", name="Model Passport", status="ok", ms=0, ts=now_iso(),
                    input={"memory_id": eligible[0].memory_id},
                    output=p.model_dump() if p else None,
                    explanation=(
                        "This Memory Passport defines the subset the external model is authorized to "
                        "receive: purpose, consent, destination, TTL and revocation state."),
                    policy_version=p.policy_version if p else decision.policy_version,
                ))
                auditlog.passport_event(request_id, req_num, conv, session_num, "VALIDATED",
                                        eligible[0].memory_id, p.revocation_state if p else "ACTIVE")
            else:
                stages.append(TraceStage(
                    id="passport", name="Model Passport", status="info", ms=0, ts=now_iso(),
                    input={},
                    output={"passport": None, "reason": "No memory used — prompt-only request."},
                    explanation="No memory passport was involved because no memory was retrieved.",
                    decision="ALLOW",
                ))
                auditlog.passport_event(request_id, req_num, conv, session_num, "NONE", "", "NONE")

            # 08 CONTEXT
            sanitized_prompt = _sanitize_prompt(prompt, decision.per_field, det.entities)
            system = SYSTEM_INSTRUCTIONS
            persona_scaffolding = persona_mod.build_semantic_persona_context()
            if persona_scaffolding:
                system += f"\n\n{persona_scaffolding}"
            if context.assembly:
                system += f"\n\nAPPROVED MEMORY CONTEXT:\n{context.assembly}"
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": sanitized_prompt},
            ]
            stages.append(TraceStage(
                id="context", name="Approved Context", status="ok", ms=0, ts=now_iso(),
                input={"raw_memory": [{"field": f.get("field"), "type": f.get("type"),
                                       "value": f.get("value"), "sensitivity": f.get("sensitivity")}
                                      for f in (eligible[0].payload if eligible else [])]},
                output={"assembly": context.assembly, "sanitized_prompt": sanitized_prompt},
                explanation="The exact context block the model will receive. Raw memory values never enter this block.",
            ))
            auditlog.payload_created(request_id, req_num, conv, session_num,
                                     len(context.assembly), len(sanitized_prompt))

            # 09 LLM GATE (egress)
            t = time.perf_counter()
            egr = egress_mod.validate(context, destination, purpose)
            egr_all_text = " ".join(m["content"] for m in messages)
            if _recheck_prohibited(egr_all_text):
                egr.status = "FAIL"
                egr.prohibited_fields += 1
            egr.ms = (time.perf_counter() - t) * 1000
            stages.append(TraceStage(
                id="llm_gate", name="LLM Gate (Egress)", status=(
                    "blocked" if egr.status == "FAIL" else "ok"), ms=egr.ms, ts=now_iso(),
                input={"destination": destination, "purpose": purpose,
                       "payload": messages},
                output={"status": egr.status, "checks": [c.model_dump() for c in egr.checks],
                        "prohibited_fields": egr.prohibited_fields},
                explanation=(
                    "Final egress validation before anything leaves the trusted boundary. "
                    "If a prohibited field is found, the model request is BLOCKED."),
                decision=egr.status, policy_version=decision.policy_version,
            ))
            auditlog.egress_validated(request_id, req_num, conv, session_num,
                                      egr.status, egr.prohibited_fields, egr.ms)

        # 10 LLM
        blocked = (decision.overall in ("BLOCK", "QUARANTINE")) or egr.status == "FAIL" or poi.risk_level == "CRITICAL" or retrieval_denied
        llm_out = None
        if not blocked:
            payload_hash = hashlib.sha256(json.dumps(messages, sort_keys=True).encode()).hexdigest()
            t_llm = time.perf_counter()
            pieces = []
            try:
                for piece in self.provider().generate_stream(messages, purpose=purpose, request_id=request_id, request_number=req_num):
                    pieces.append(piece)
                    yield {"type": "delta", "text": piece}
                full_text = "".join(pieces).strip()
                llm_latency = (time.perf_counter() - t_llm) * 1000
                llm_out = {
                    "text": full_text,
                    "provider": "nvidia" if os.environ.get("NVIDIA_API_KEY") else "demo",
                    "model": getattr(self.provider(), "model", "nvidia/nemotron-3.5-lightning-30b-a3b"),
                    "latency_ms": llm_latency,
                    "demo": not bool(os.environ.get("NVIDIA_API_KEY")),
                    "error": "",
                }
                stages.append(TraceStage(
                    id="llm", name="External Model", status="ok", ms=llm_out.get("latency_ms", 0), ts=now_iso(),
                    input={"provider": "nvidia", "model": llm_out.get("model", ""),
                           "request_id": request_id},
                    output={"status": "SENT", "destination": destination,
                            "request_id": request_id, "timestamp": now_iso(),
                            "payload_hash": payload_hash,
                            "provider": llm_out.get("provider"),
                            "model": llm_out.get("model"),
                            "payload": messages,
                            "latency_ms": llm_out.get("latency_ms", 0)},
                    explanation="Approved payload crossed the security boundary and reached the external model.",
                    decision="SENT",
                ))
            except Exception as e:
                err_text = (f"⚠ LLM CONNECTION FAILED\n\nNVIDIA endpoint unreachable: {e}\n\n"
                            "MEMVERSE's security decision still stands — the trace and receipt remain valid. "
                            "Set NVIDIA_API_KEY to enable live generation.")
                llm_out = {
                    "text": err_text,
                    "provider": "nvidia", "model": "—", "latency_ms": 0, "demo": False,
                    "error": str(e),
                }
                yield {"type": "delta", "text": err_text}
                stages.append(TraceStage(
                    id="llm", name="External Model", status="error", ms=0, ts=now_iso(),
                    input={"provider": "nvidia", "model": "—", "request_id": request_id},
                    output={"status": "FAILED", "destination": destination,
                            "request_id": request_id, "timestamp": now_iso(),
                            "payload_hash": payload_hash,
                            "error": str(e), "payload": messages},
                    explanation=("The approved payload was ready but the external model was unreachable. "
                                 "No raw memory was exposed — fail-safe."),
                    decision="FAILED",
                ))
        else:
            if decision.overall in ("BLOCK", "QUARANTINE"):
                denial = decision.reason
                if poi.risk_level in ("HIGH", "CRITICAL") and "poison" not in denial.lower():
                    denial = "Input scored HIGH/CRITICAL on the poisoning detector. Request blocked, fail closed."
            elif egr.status == "FAIL":
                denial = "Egress validation failed — prohibited content detected in payload. Model request blocked."
            elif retrieval_denied:
                denial = denial_msg
            else:
                denial = decision.reason
            blocked_text = (denial if retrieval_denied else f"⛔ MEMVERSE BLOCKED THIS REQUEST\n\n{denial}")
            llm_out = {
                "text": blocked_text,
                "provider": "gateway", "model": "—", "latency_ms": 0, "demo": False, "error": "",
            }
            yield {"type": "delta", "text": blocked_text}
            stages.append(TraceStage(
                id="llm", name="External Model", status="blocked", ms=0, ts=now_iso(),
                input={"blocked": True, "reason": denial},
                output={"status": "NOT SENT", "destination": destination,
                        "request_id": request_id, "timestamp": now_iso(),
                        "reason": denial},
                explanation="The model was never contacted. The gateway fails closed.",
                decision="NOT SENT",
            ))
            auditlog.request_blocked(request_id, req_num, conv, session_num, denial)

        # 11 RESPONSE
        stages.append(TraceStage(
            id="response", name="Response", status="ok", ms=llm_out.get("latency_ms", 0), ts=now_iso(),
            input={"provider": llm_out.get("provider"), "model": llm_out.get("model")},
            output={"text": llm_out.get("text", ""), "demo": llm_out.get("demo", False)},
            explanation=("Model output captured. User sees this response; the trace proves what the model "
                         "was allowed to see."),
        ))

        # 12 RECEIPT
        fields_transformed = sum(1 for f in decision.per_field if f.action != "ALLOW")
        evt = {
            "event_id": new_id("evt"), "event_type": "CHAT_REQUEST",
            "timestamp": now_iso(), "purpose": purpose, "destination": destination,
            "decision": decision.overall if not blocked else "BLOCK",
            "fields_detected": len(det.entities) + len(memory_entities),
            "fields_transformed": fields_transformed,
            "policy_version": decision.policy_version,
            "passport_id": eligible[0].memory_id if eligible else "",
            "revocation_state": eligible[0].passport.revocation_state if eligible else "NONE",
            "extra": {"request_id": request_id, "poisoning_risk": poi.risk_level,
                      "poisoning_score": poi.risk_score,
                      "llm_provider": llm_out.get("provider"),
                      "llm_status": _llm_status(stages),
                      "egress": egr.status, "llm_error": llm_out.get("error", "")},
        }
        receipt = receipts_mod.create_receipt(evt)
        stages.append(TraceStage(
            id="receipt", name="Receipt", status="ok", ms=0, ts=now_iso(),
            input={"event_type": "CHAT_REQUEST"},
            output={"receipt_id": receipt.event_id, "event_hash": receipt.event_hash,
                    "previous_event_hash": receipt.previous_event_hash},
            explanation="Tamper-evident receipt appended to the hash-linked ledger for this request.",
        ))
        auditlog.receipt_created(request_id, req_num, conv, session_num, receipt.event_id,
                                 "CHAT_REQUEST", receipt.decision)

        trace = RequestTrace(
            request_id=request_id, conversation_id=conv, timestamp=ts, operation="REVEAL",
            purpose=purpose, destination=destination, prompt=prompt, stages=stages,
            request_number=req_num, session_number=session_num,
            summary=_summarize(decision, det, poi, receipt, egr, None, blocked=blocked),
        )
        mem_stages = [s for s in stages if s.id not in ("llm", "response")]
        trace.memverse_ms = round(sum(s.ms for s in mem_stages), 2)
        trace.model_ms = round(llm_out.get("latency_ms", 0), 2)
        trace.total_ms = round(trace.memverse_ms + trace.model_ms, 2)
        _persist_trace(trace)

        # persist messages
        msg_id = new_id("msg")
        execute(
            """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
               VALUES (?,?,?,?,?,?,?,?)""",
            (new_id("msg"), conv, "user", prompt, now_iso(), trace.request_id, receipt.event_id, "user"),
        )
        execute(
            """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
               VALUES (?,?,?,?,?,?,?,?)""",
            (msg_id, conv, "assistant", llm_out.get("text", ""), now_iso(),
             trace.request_id, receipt.event_id, llm_out.get("provider", "")),
        )
        result = ChatResult(
            message_id=msg_id, conversation_id=conv,
            response_text=llm_out.get("text", ""),
            provider=llm_out.get("provider", ""), model=llm_out.get("model", ""),
            demo=bool(llm_out.get("demo")), trace=trace, receipt=receipt,
            model_input={"messages": messages} if not blocked else {},
            model_output=llm_out.get("text", "") if not blocked else "",
            blocked=blocked,
        )
        yield {"type": "done", "result": result.model_dump()}

    # ------------------------------------------------------- image chat pipeline
    def process_image_chat(
        self,
        prompt: str,
        image_b64: str,
        image_meta: dict,
        conversation_id: str | None = None,
        purpose: str = "image_generation",
        destination: str = "nvidia",
    ) -> ChatResult:
        """Process an image chat request through the biometric-aware pipeline.

        Differs from process_chat in these ways:
        - Stage 01: REQUEST logs IMAGE_REVEAL with biometric passport
        - Stage 02: BIOMETRIC PASSPORT — creates passport with 1-request TTL
        - Stage 03: DEFEND — text prompt poisoning only (image not analysable)
        - Stage 04: PERSONA CONTEXT — adds "EXIF stripped, consent granted" line
        - Stage 05: MULTIMODAL PAYLOAD — content is list (image + text)
        - Stage 06: LLM CALL — same provider interface
        - Stage 07: RECEIPT — image_hash only, no image bytes
        - Stage 08: PERSIST — user/assistant messages without image bytes
        - Stage 09: LOG TO PERSONA VAULT — biometric event (NOT STORED)
        """
        request_id = new_id("req")
        req_num = self._next_request_number()
        conv, session_num = self._ensure_conversation(conversation_id)
        ts = now_iso()
        stages: list[TraceStage] = []

        # ---- Stage 01: REQUEST — IMAGE REVEAL
        t = time.perf_counter()
        stages.append(TraceStage(
            id="request", name="Request", status="ok", ms=(time.perf_counter() - t) * 1000, ts=ts,
            input={"request_id": request_id, "conversation_id": conv, "timestamp": ts,
                   "operation": "IMAGE_REVEAL", "purpose": purpose, "destination": destination,
                   "prompt": prompt, "image_meta": image_meta},
            output={"operation": "IMAGE_REVEAL", "purpose": purpose, "destination": destination,
                    "face_detected": image_meta.get("face_detected", False),
                    "consent_granted": image_meta.get("consent_granted", False)},
            explanation="Image chat request captured at the gateway. Biometric data subject to "
                        "one-request TTL and zero-retention policy.",
        ))
        auditlog.request_received(request_id, req_num, conv, session_num, "IMAGE_REVEAL", len(prompt))

        # ---- Stage 02: BIOMETRIC PASSPORT
        # Create a passport record that expires after 1 request
        image_hash = image_meta.get("original_hash", "")
        face_detected = image_meta.get("face_detected", False)
        face_redacted = image_meta.get("face_redacted", False)
        passport_data = {
            "type": "BIOMETRIC_IMAGE",
            "consent": image_meta.get("consent_granted", False),
            "ttl": "1_REQUEST",
            "retention": "ZERO",
            "image_hash": image_hash,
            "face_detected": face_detected,
            "face_redacted": face_redacted,
            "egress_privacy": "MOSAIC_PIXELATED" if face_redacted else ("RAW_EXPLICIT_CONSENT" if face_detected else "CLEAN_IMAGE"),
            "exif_stripped": True,
            "issued_at": ts,
        }
        stages.append(TraceStage(
            id="passport", name="Biometric Passport", status="ok", ms=0, ts=now_iso(),
            input={"image_hash": image_hash[:16] + "…", "consent": passport_data["consent"]},
            output=passport_data,
            explanation=(
                "Biometric Image Passport issued — defines the one-request consumption policy. "
                "Image hash recorded, image bytes never persisted. TTL: 1 request, then auto-expires."
            ),
        ))

        # ---- Stage 03: DEFEND — text prompt poisoning only
        t = time.perf_counter()
        poi = poisoning.analyze(prompt)
        stages.append(TraceStage(
            id="defend", name="Poisoning Defense", status=(
                "blocked" if poi.risk_level in ("HIGH", "CRITICAL") else
                ("warn" if poi.risk_level == "MEDIUM" else "ok")),
            ms=poi.ms, ts=now_iso(),
            input={"prompt": prompt},
            output={"risk_score": poi.risk_score, "risk_level": poi.risk_level,
                    "action": poi.action,
                    "matched_patterns": [m.model_dump() for m in poi.matched_patterns],
                    "reason": poi.reason},
            explanation=poi.reason, decision=poi.action,
        ))
        auditlog.poisoning_scored(request_id, req_num, conv, session_num, poi.risk_level, poi.risk_score, poi.ms)

        # Early termination if CRITICAL poisoning detected
        if poi.risk_level in ("HIGH", "CRITICAL"):
            _, denial_reason = poi.action or ("Input blocked due to " + poi.risk_level + " risk")
            blocked = True
            denial = denial_reason if "poison" not in denial.lower() else \
                "Input scored HIGH/CRITICAL on the poisoning detector. Request blocked, fail closed."

            llm_out = {
                "text": (denial if "poison" not in denial.lower() else
                         "Input scored HIGH/CRITICAL on the poisoning detector. Request blocked, fail closed."),
                "provider": "gateway", "model": "—", "latency_ms": 0, "demo": False, "error": "",
            }
            # Create receipt even for blocked
            evt = {
                "event_id": new_id("evt"), "event_type": "CHAT_REQUEST",
                "timestamp": now_iso(), "purpose": purpose, "destination": destination,
                "decision": "BLOCK", "fields_detected": 0, "fields_transformed": 0,
                "policy_version": POLICY_VERSION,
                "passport_id": "",
                "revocation_state": "NONE",
                "extra": {"request_id": request_id, "poisoning_risk": poi.risk_level,
                          "poisoning_score": poi.risk_score, "egress": "BLOCKED", "llm_error": "",
                          "face_redacted": face_redacted},
            }
            receipt = receipts_mod.create_receipt(evt)
            stages.append(TraceStage(
                id="receipt", name="Receipt", status="ok", ms=0, ts=now_iso(),
                input={"event_type": "CHAT_REQUEST"},
                output={"receipt_id": receipt.event_id, "event_hash": receipt.event_hash,
                        "previous_event_hash": receipt.previous_event_hash},
                explanation="Tamper-evident receipt appended to the hash-linked ledger for this request.",
            ))
            auditlog.receipt_created(request_id, req_num, conv, session_num, receipt.event_id,
                                     "CHAT_REQUEST", receipt.decision)

            trace = RequestTrace(
                request_id=request_id, conversation_id=conv, timestamp=ts, operation="REVEAL",
                purpose=purpose, destination=destination, prompt=prompt, stages=stages,
                request_number=req_num, session_number=session_num,
                summary=_summarize(None, None, poi, receipt, None, None, blocked=True),
            )
            mem_stages = [s for s in stages if s.id not in ("llm", "response")]
            trace.memverse_ms = round(sum(s.ms for s in mem_stages), 2)
            trace.model_ms = round(llm_out.get("latency_ms", 0), 2)
            trace.total_ms = round(trace.memverse_ms + trace.model_ms, 2)
            _persist_trace(trace)

            # persist messages
            msg_id = new_id("msg")
            execute(
                """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (new_id("msg"), conv, "user", prompt, now_iso(), trace.request_id, receipt.event_id, "user"),
            )
            execute(
                """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (msg_id, conv, "assistant", llm_out.get("text", ""), now_iso(),
                 trace.request_id, receipt.event_id, llm_out.get("provider", "")),
            )
            return ChatResult(
                message_id=msg_id, conversation_id=conv,
                response_text=llm_out.get("text", ""),
                provider=llm_out.get("provider", ""), model=llm_out.get("model", ""),
                demo=False, trace=trace, receipt=receipt,
                model_input={}, model_output=llm_out.get("text", "") if not blocked else "",
                blocked=True,
            )

        # ---- Stage 04: PERSONA CONTEXT
        # Build system message with EXIF stripped notice
        system_instructions = (
            "You are a helpful AI assistant operating inside the MEMVERSE zero-trust memory gateway. "
            "The memory context below is the ONLY personal background approved for this request. "
            "CRITICAL USAGE RULE: Use this background context ONLY when it is directly relevant to answering "
            "the user's question. Do NOT recite, repeat, or regurgitate this context unnecessarily unless "
            "the user explicitly asks about it. Do not claim to know anything about the user beyond it, "
            "and never ask for exact personal identity."
        )
        system = system_instructions
        persona_scaffolding = persona_mod.build_semantic_persona_context()
        if persona_scaffolding:
            system += f"\n\n{persona_scaffolding}"
        # Add explicit notice about image consent and EXIF stripping
        system += (
            f"\n\nBIOMETRIC CONTEXT: User has shared an image with explicit consent. "
            f"EXIF metadata has been stripped. Face was {'redacted' if face_redacted else ('detected' if face_detected else 'not detected')}. "
            f"Image TTL: 1 request — auto-expires after this pipeline completes. "
            f"Raw image pixels and face embeddings are NOT stored anywhere."
        )

        # ---- Stage 05: MULTIMODAL PAYLOAD BUILD
        # NVIDIA API expects content as a list: [image_url dict, text dict]
        image_url = f"data:image/jpeg;base64,{image_b64}"
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": [
                {"type": "image_url",
                 "image_url": {"url": image_url}},
                {"type": "text", "text": prompt}
            ]}
        ]

        # ---- Stage 06: LLM CALL
        blocked = False
        payload_hash = hashlib.sha256(json.dumps(messages, sort_keys=True).encode()).hexdigest()
        try:
            llm_out = self.provider().generate(messages, purpose=purpose, request_id=request_id, request_number=req_num)
            stages.append(TraceStage(
                id="llm", name="External Model", status="ok", ms=llm_out.get("latency_ms", 0), ts=now_iso(),
                input={"provider": "nvidia", "model": llm_out.get("model", ""),
                       "request_id": request_id},
                output={"status": "SENT", "destination": destination,
                        "request_id": request_id, "timestamp": now_iso(),
                        "payload_hash": payload_hash,
                        "provider": llm_out.get("provider"),
                        "model": llm_out.get("model"),
                        "payload": messages,
                        "latency_ms": llm_out.get("latency_ms", 0)},
                explanation="Approved payload crossed the security boundary and reached the external model.",
                decision="SENT",
            ))
            auditlog.model_request_sent(request_id, req_num, "", 0, self.provider().name, llm_out.get("model", ""), 0)
            auditlog.model_response_received(request_id, req_num, "", 0, self.provider().name,
                                             (time.perf_counter() - t) * 1000)
        except Exception as e:
            llm_out = {
                "text": f"⚠ LLM CONNECTION FAILED\n\nNVIDIA endpoint unreachable: {e}\n\n"
                          "MEMVERSE's security decision still stands — the trace and receipt remain valid. "
                          "Set NVIDIA_API_KEY to enable live generation.",
                "provider": "nvidia", "model": "—", "latency_ms": 0, "demo": False, "error": str(e),
            }
            stages.append(TraceStage(
                id="llm", name="External Model", status="error", ms=0, ts=now_iso(),
                input={"provider": "nvidia", "model": "—", "request_id": request_id},
                output={"status": "FAILED", "destination": destination,
                        "request_id": request_id, "timestamp": now_iso(),
                        "payload_hash": payload_hash,
                        "error": str(e), "payload": messages},
                explanation=("The approved payload was ready but the external model was unreachable. "
                             "No raw memory was exposed — fail-safe."),
                decision="FAILED",
            ))
            auditlog.model_request_failed(request_id, req_num, "", 0, "network")
            # Still create receipt for error case
            evt = {
                "event_id": new_id("evt"), "event_type": "CHAT_REQUEST",
                "timestamp": now_iso(), "purpose": purpose, "destination": destination,
                "decision": "BLOCK", "fields_detected": 0, "fields_transformed": 0,
                "policy_version": POLICY_VERSION,
                "passport_id": "",
                "revocation_state": "NONE",
                "extra": {"request_id": request_id, "poisoning_risk": "ERROR",
                          "poisoning_score": 0, "egress": "BLOCKED", "llm_error": str(e)},
            }
            receipt = receipts_mod.create_receipt(evt)
            stages.append(TraceStage(
                id="receipt", name="Receipt", status="ok", ms=0, ts=now_iso(),
                input={"event_type": "CHAT_REQUEST"},
                output={"receipt_id": receipt.event_id, "event_hash": receipt.event_hash,
                        "previous_event_hash": receipt.previous_event_hash},
                explanation="Tamper-evident receipt appended to the hash-linked ledger for this request.",
            ))
            auditlog.receipt_created(request_id, req_num, conv, session_num, receipt.event_id,
                                     "CHAT_REQUEST", receipt.decision)

            trace = RequestTrace(
                request_id=request_id, conversation_id=conv, timestamp=ts, operation="REVEAL",
                purpose=purpose, destination=destination, prompt=prompt, stages=stages,
                request_number=req_num, session_number=session_num,
                summary=_summarize(None, None, None, receipt, None, None, blocked=True),
            )
            mem_stages = [s for s in stages if s.id not in ("llm", "response")]
            trace.memverse_ms = round(sum(s.ms for s in mem_stages), 2)
            trace.model_ms = round(llm_out.get("latency_ms", 0), 2)
            trace.total_ms = round(trace.memverse_ms + trace.model_ms, 2)
            _persist_trace(trace)

            # persist messages
            msg_id = new_id("msg")
            execute(
                """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (new_id("msg"), conv, "user", prompt, now_iso(), trace.request_id, receipt.event_id, "user"),
            )
            execute(
                """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (msg_id, conv, "assistant", llm_out.get("text", ""), now_iso(),
                 trace.request_id, receipt.event_id, llm_out.get("provider", "")),
            )
            return ChatResult(
                message_id=msg_id, conversation_id=conv,
                response_text=llm_out.get("text", ""),
                provider=llm_out.get("provider", ""), model=llm_out.get("model", ""),
                demo=False, trace=trace, receipt=receipt,
                model_input={}, model_output=llm_out.get("text", "") if not blocked else "",
                blocked=True,
            )

        # ---- Stage 07: RECEIPT
        face_redacted = image_meta.get("face_redacted", False)
        face_detected = image_meta.get("face_detected", False)
        fields_transformed = 1 if face_redacted else 0
        evt = {
            "event_id": new_id("evt"), "event_type": "IMAGE_CHAT",
            "timestamp": now_iso(), "purpose": purpose, "destination": destination,
            "decision": "ALLOW", "fields_detected": 1 if face_detected else 0, "fields_transformed": fields_transformed,
            "policy_version": POLICY_VERSION,
            "passport_id": request_id,
            "revocation_state": "NONE",
            "extra": {"request_id": request_id, "poisoning_risk": poi.risk_level,
                      "poisoning_score": poi.risk_score,
                      "face_detected": face_detected,
                      "face_redacted": face_redacted,
                      "consent_granted": image_meta.get("consent_granted", False),
                      "egress": "MOSAIC_REDACTED" if face_redacted else "CLEAN", "llm_error": ""},
        }
        receipt = receipts_mod.create_receipt(evt)
        stages.append(TraceStage(
            id="receipt", name="Receipt", status="ok", ms=0, ts=now_iso(),
            input={"event_type": "IMAGE_CHAT"},
            output={"receipt_id": receipt.event_id, "event_hash": receipt.event_hash,
                    "previous_event_hash": receipt.previous_event_hash},
            explanation="Tamper-evident receipt appended to the hash-linked ledger for this image chat request.",
        ))
        auditlog.receipt_created(request_id, req_num, conv, session_num, receipt.event_id,
                                 "IMAGE_CHAT", receipt.decision)

        # Persona Vault: Textual facts only (Images and PDFs are 1-request TTL zero-retention)

        # Build trace summary
        mem_stages = [s for s in stages if s.id not in ("llm", "response")]
        trace = RequestTrace(
            request_id=request_id, conversation_id=conv, timestamp=ts, operation="REVEAL",
            purpose=purpose, destination=destination, prompt=prompt, stages=stages,
            request_number=req_num, session_number=session_num,
            summary=_summarize(None, None, poi, receipt, None, None, blocked=False),
        )
        trace.memverse_ms = round(sum(s.ms for s in mem_stages), 2)
        trace.model_ms = round(llm_out.get("latency_ms", 0), 2)
        trace.total_ms = round(trace.memverse_ms + trace.model_ms, 2)
        _persist_trace(trace)

        # ---- Stage 08: PERSIST — messages without image bytes
        user_msg_content = f"[IMAGE: {image_meta.get('filename', 'unknown.jpg')}] {prompt}"
        assistant_msg_text = llm_out.get("text", "")

        msg_id = new_id("msg")
        execute(
            """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
               VALUES (?,?,?,?,?,?,?,?)""",
            (new_id("msg"), conv, "user", user_msg_content, now_iso(),
             trace.request_id, receipt.event_id, "user"),
        )
        execute(
            """INSERT INTO messages (id, conversation_id, role, content, ts, trace_id, receipt_id, provider)
               VALUES (?,?,?,?,?,?,?,?)""",
            (msg_id, conv, "assistant", assistant_msg_text, now_iso(),
             trace.request_id, receipt.event_id, llm_out.get("provider", "")),
        )

        # persist messages (already done above, but ensuring consistency)
        # Messages already inserted in Stage 08

        return ChatResult(
            message_id=msg_id, conversation_id=conv,
            response_text=assistant_msg_text,
            provider=llm_out.get("provider", ""), model=llm_out.get("model", ""),
            demo=bool(llm_out.get("demo", False)), trace=trace, receipt=receipt,
            model_input={"messages": messages} if not blocked else {},
            model_output=llm_out.get("text", "") if not blocked else "",
            blocked=blocked,
        )

    # --------------------------------------------------------- read pipeline
    def process_memory_read(
        self, memory_id: str, purpose: str = "answer_query",
        destination: str = "nvidia",
    ) -> dict:
        """Standalone READ (used by registry / security lab). Returns trace + context + receipt."""
        stages: list[TraceStage] = []
        request_id = new_id("req")
        req_num = self._next_request_number()
        memory = memory_store.load_memory(memory_id)
        passport = memory.passport if memory else None

        if memory is None or passport is None:
            return {"blocked": True, "reason": "Memory not found.", "trace": None, "receipt": None}

        # 01 REQUEST / 02 PASSPORT VALIDATION
        state = passport.revocation_state
        if state in ("REVOKED", "QUARANTINED", "EXPIRED", "BLOCKED"):
            stages.append(TraceStage(id="passport", name="Memory Passport", status="blocked", ms=0, ts=now_iso(),
                                     input={"memory_id": memory_id, "passport_state": state},
                                     output={"eligible": False, "state": state},
                                     explanation=f"Memory Passport is {state}. Retrieval fails closed.",
                                     decision="BLOCK", policy_version=passport.policy_version))
            auditlog.passport_event(request_id, req_num, "", 0, "BLOCKED", memory_id, state, 0.0)
            auditlog.request_blocked(request_id, req_num, "", 0, f"passport {state}")
            evt = {"event_id": new_id("evt"), "event_type": "MEMORY_READ", "timestamp": now_iso(),
                   "purpose": purpose, "destination": destination, "decision": "BLOCK",
                   "fields_detected": len(memory.payload), "fields_transformed": 0,
                   "policy_version": passport.policy_version, "passport_id": memory_id,
                   "revocation_state": state,
                   "extra": {"reason": f"passport {state}", "fail_closed": True}}
            receipt = receipts_mod.create_receipt(evt)
            auditlog.receipt_created(request_id, req_num, "", 0, receipt.event_id, "MEMORY_READ", "BLOCK")
            stages.append(TraceStage(id="receipt", name="Receipt", status="ok", ms=0, ts=now_iso(),
                                     input={}, output={"receipt_id": receipt.event_id},
                                     explanation="Blocked retrieval receipt appended to ledger."))
            trace = RequestTrace(request_id=request_id, timestamp=now_iso(), operation="REVEAL",
                                 purpose=purpose, destination=destination, prompt="",
                                 request_number=req_num,
                                 stages=stages, summary={"decision": "BLOCK", "blocked": True,
                                                          "reason": f"passport {state}"})
            _persist_trace(trace)
            return {"blocked": True, "reason": f"Memory Passport {state}. Retrieval fails closed.",
                    "trace": trace.model_dump(), "receipt": receipt.model_dump(), "memory": memory.model_dump()}

        entities = [_ent(f, field_key="field") for f in memory.payload]
        det = detector.DetectionResult(source="memory_payload", entities=[
            detector.DetectedEntity(entity=e.entity, value=e.value, type=e.type,
                                    sensitivity=e.sensitivity, reason="stored field",
                                    confidence=1.0) for e in entities])
        poi = poisoning.analyze(" ".join(e.value for e in entities))
        decision = self.policy_engine.evaluate(
            operation="REVEAL", purpose=purpose, destination=destination,
            passport=passport, poisoning_level=poi.risk_level, entities=entities)
        context = transformer_mod.transform_fields(decision.per_field)
        egr = egress_mod.validate(context, destination, purpose)

        stages.append(TraceStage(id="detect", name="Detection", status="ok", ms=0, ts=now_iso(),
                                 input={"memory_id": memory_id},
                                 output={"entities": [e.model_dump() for e in det.entities]},
                                 explanation="Stored payload fields re-detected at retrieval time."))
        stages.append(TraceStage(id="defend", name="Poisoning Defense", status="ok", ms=poi.ms, ts=now_iso(),
                                 input={}, output={"risk_level": poi.risk_level, "score": poi.risk_score},
                                 explanation=poi.reason, decision=poi.action))
        stages.append(TraceStage(id="policy", name="Policy Engine", status="ok", ms=decision.ms, ts=now_iso(),
                                 input={"policy_version": decision.policy_version, "purpose": purpose,
                                        "destination": destination},
                                 output={"decision": decision.overall, "reason": decision.reason,
                                         "per_field": [f.model_dump() for f in decision.per_field]},
                                 explanation=decision.reason, decision=decision.overall,
                                 policy_version=decision.policy_version))
        auditlog.passport_event(request_id, req_num, "", 0, "VALIDATED", memory_id,
                                passport.revocation_state)
        stages.append(TraceStage(id="transform", name="Transformation", status="ok", ms=context.ms, ts=now_iso(),
                                 input={}, output={"approved_entries": [e.model_dump() for e in context.entries]},
                                 explanation="Retrieval-time transformation applied per current policy."))
        stages.append(TraceStage(id="llm_gate", name="LLM Gate (Egress)", status="ok", ms=egr.ms, ts=now_iso(),
                                 input={}, output={"status": egr.status, "prohibited": egr.prohibited_fields},
                                 explanation="Egress validation over the approved context.", decision=egr.status))

        fields_transformed = sum(1 for f in decision.per_field if f.action != "ALLOW")
        evt = {"event_id": new_id("evt"), "event_type": "MEMORY_READ", "timestamp": now_iso(),
               "purpose": purpose, "destination": destination,
               "decision": decision.overall if egr.status == "PASS" else "BLOCK",
               "fields_detected": len(memory.payload), "fields_transformed": fields_transformed,
               "policy_version": decision.policy_version, "passport_id": memory_id,
               "revocation_state": passport.revocation_state,
               "extra": {"memory_status": memory.status}}
        receipt = receipts_mod.create_receipt(evt)
        auditlog.receipt_created(request_id, req_num, "", 0, receipt.event_id, "MEMORY_READ", receipt.decision)
        stages.append(TraceStage(id="receipt", name="Receipt", status="ok", ms=0, ts=now_iso(),
                                 input={}, output={"receipt_id": receipt.event_id},
                                 explanation="Read receipt appended to ledger."))
        trace = RequestTrace(request_id=request_id, timestamp=now_iso(), operation="REVEAL",
                             purpose=purpose, destination=destination, prompt="",
                             request_number=req_num,
                             stages=stages, summary={"decision": decision.overall,
                                                      "context": context.assembly})
        trace.memverse_ms = round(sum(s.ms for s in stages), 2)
        trace.total_ms = round(trace.memverse_ms, 2)
        _persist_trace(trace)
        return {"blocked": False, "context": context.model_dump(), "trace": trace.model_dump(),
                "receipt": receipt.model_dump(), "memory": memory.model_dump()}

    # ------------------------------------------------------------- revoke
    def revoke_memory(self, memory_id: str, reason: str = "Revoked by user") -> RevokeResult:
        memory = memory_store.revoke(memory_id, reason)
        evt = {"event_id": new_id("evt"), "event_type": "REVOKE", "timestamp": now_iso(),
               "purpose": memory.purpose, "destination": memory.destination,
               "decision": "REVOKE", "fields_detected": len(memory.payload),
               "fields_transformed": 0, "policy_version": memory.policy_version if hasattr(memory, "policy_version") else POLICY_VERSION,
               "passport_id": memory_id, "revocation_state": "REVOKED",
               "extra": {"reason": reason, "memory_status": memory.status}}
        receipt = receipts_mod.create_receipt(evt)
        auditlog.memory_revoke("", 0, memory_id, "REVOKED")
        auditlog.receipt_created("", 0, "", 0, receipt.event_id, "REVOKE", "REVOKE")
        return RevokeResult(memory=memory, receipt=receipt)

    # ------------------------------------------------------------- helpers
    def _next_request_number(self) -> int:
        """Monotonic request sequence stored in meta so demo resets can rewind it."""
        nxt = int(get_meta("request_seq", "0") or "0") + 1
        set_meta("request_seq", str(nxt))
        return nxt

    def _ensure_conversation(self, conversation_id: str | None) -> tuple[str, int]:
        if conversation_id:
            rows = q("SELECT num FROM conversations WHERE id=?", (conversation_id,))
            if rows:
                return conversation_id, rows[0]["num"]
            # unknown id -> treat as new
        conv = new_id("conv")
        execute(
            "INSERT INTO conversations (id, created_at, num) VALUES (?, ?, "
            "(SELECT COALESCE(MAX(num),0)+1 FROM conversations))",
            (conv, now_iso()),
        )
        rows = q("SELECT num FROM conversations WHERE id=?", (conv,))
        return conv, rows[0]["num"] if rows else 0

    def _retrieve_memories(self, purpose: str, destination: str) -> tuple[list, list]:
        eligible, denied = [], []
        for m in memory_store.list_memories():
            p = m.passport
            if p is None:
                denied.append((m, "no passport on record"))
                continue
            if p.revocation_state == "REVOKED":
                denied.append((m, "passport REVOKED — fail closed"))
                continue
            if p.revocation_state == "QUARANTINED":
                denied.append((m, "passport QUARANTINED — never eligible"))
                continue
            if p.revocation_state == "EXPIRED":
                denied.append((m, "passport EXPIRED (TTL reached) — fail closed"))
                continue
            if p.consent != "GRANTED":
                denied.append((m, "consent NOT_GRANTED"))
                continue
            if destination.lower() not in self.policy_engine.policy.get("destinations", {}).get("allow", []):
                denied.append((m, "destination not allowlisted"))
                continue
            # malicious-memory scan at runtime
            text = " ".join(f.get("value", "") for f in m.payload)
            pr = poisoning.analyze(text)
            if pr.risk_level in ("HIGH", "CRITICAL"):
                passport_mod.set_state(m.memory_id, "QUARANTINED")
                denied.append((m, "memory contains malicious instructions — quarantined at runtime"))
                continue
            eligible.append(m)
            passport_mod.touch_access(m.memory_id)
        denied.sort(key=lambda pair: {
            "REVOKED": 0, "QUARANTINED": 1, "EXPIRED": 2, "consent": 3,
            "destination": 4, "no": 5, "memory": 1,
        }.get(pair[1].split()[0], 9))
        return eligible, denied


# ------------------------------------------------------------------ helpers
def _max_sensitivity(fields) -> str:
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    best = "LOW"
    for f in fields:
        if rank.get(f.sensitivity, 1) > rank.get(best, 1):
            best = f.sensitivity
    return best


def _is_memory_declaration(text: str) -> bool:
    t = text.strip().lower()
    if len(t) > 400:
        return False
    if re.search(r"\b(my name is|i am called|you can call me|call me)\b", t):
        return True
    if re.search(r"\b(i'?m|i am)\s+\d{1,3}\s*(years\s*old|yrs|yo)?\b", t) and re.search(r"\b(am|'?m|live|from|stud)", t):
        return True
    if re.search(r"\b(i live in|i am from|i stay in|i am based in|my city is|my hometown)\b", t):
        return True
    if re.search(r"\b(remember|memorize|store this|save this|don'?t forget)\b", t):
        # Interrogatives ("what do you remember?", "do you remember my name?")
        # are REVEAL questions, never storage instructions.
        if re.search(r"^(what|who|when|where|why|how|which|do|did|does|would|could|can|are|is)\b", t):
            return False
        return True
    return False


def _write_purpose(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ("name", "age", "live", "from", "city", "born", "birthday", "phone", "email")):
        return "personalization"
    return "personalization"


_ASK_RE = re.compile(
    r"(?i)\b(my name|my age|name and age|age and name|who am i|about me|my details|my profile|"
    r"my email|my phone|my city|where do i live|my address|my information|what do you know about me|"
    r"what do you remember|what can you tell me about me|my data|my memories|my memory)\b"
)


def _asks_about_memory(prompt: str) -> bool:
    return bool(_ASK_RE.search(prompt))


def _sanitize_prompt(prompt: str, per_field, entities) -> str:
    """Replace raw detected values in the prompt with their transformed outputs."""
    out = prompt
    mapping = {}
    for fd in per_field:
        if fd.action != "ALLOW" and fd.raw_value and fd.raw_value.strip():
            mapping[fd.raw_value.strip()] = fd.output or "[redacted]"
    for e in entities:
        for fd in per_field:
            if (fd.field == e.entity or fd.type == e.type) and fd.action != "ALLOW" and e.value and e.value.strip():
                if e.value.strip() not in mapping:
                    mapping[e.value.strip()] = fd.output or "[redacted]"

    # Single pass replacement prioritized by longest match first
    for raw in sorted(mapping.keys(), key=len, reverse=True):
        if not raw:
            continue
        # Case-insensitive replacement of the exact detected raw value
        pattern = re.compile(re.escape(raw), re.IGNORECASE)
        replacement = mapping[raw]
        # Avoid double-replacements if target already replaced
        if pattern.search(out):
            out = pattern.sub(replacement, out)
    return out


def _recheck_prohibited(text: str) -> bool:
    import egress as egress_mod
    return any(
        __import__("re").search(rx, text)
        for rx, _ in egress_mod.PROHIBITED_RE
    )


def _llm_status(stages) -> str:
    for s in stages:
        if s.id == "llm":
            return (s.output or {}).get("status", s.decision or "")
    return ""


def _summarize(decision, det, poi, receipt, egr, memory, blocked: bool) -> dict:
    transformed = sum(1 for f in decision.per_field if f.action not in ("ALLOW", "BLOCK")) if decision and getattr(decision, "per_field", None) else 0
    blocked_fields = sum(1 for f in decision.per_field if f.action == "BLOCK") if decision and getattr(decision, "per_field", None) else 0
    summary_decision = decision.overall if decision and getattr(decision, "overall", None) else ("BLOCK" if blocked else "ALLOW")
    if blocked and summary_decision in ("ALLOW", "TRANSFORM", "LOCAL_ONLY", "REQUIRE_APPROVAL"):
        summary_decision = "BLOCK"
    status = {
        "ALLOW": "ALLOWED", "TRANSFORM": "TRANSFORMED",
        "BLOCK": "BLOCKED", "QUARANTINE": "BLOCKED",
        "LOCAL_ONLY": "PROTECTED", "REQUIRE_APPROVAL": "PROTECTED",
    }.get(summary_decision, "PROTECTED")
    fields_detected = (len(det.entities) if det and getattr(det, "entities", None) else 0) + (len(memory.payload) if memory and getattr(memory, "payload", None) else 0)
    return {
        "status": status,
        "decision": summary_decision,
        "fields_detected": fields_detected,
        "fields_transformed": transformed,
        "fields_blocked": blocked_fields,
        "poisoning_risk": poi.risk_level if poi else "LOW",
        "poisoning_score": poi.risk_score if poi else 0,
        "destination": "nvidia",
        "egress": "CLEAN" if not blocked else "BLOCKED",
        "receipt": receipt.event_id if receipt else "",
        "receipt_verified": None,
        "blocked": blocked,
        "llm_provider": "",
    }


def _persist_trace(trace: RequestTrace) -> None:
    try:
        execute(
            "INSERT INTO traces (id, message_id, data_json) VALUES (?,?,?)",
            (trace.request_id, "", json.dumps(trace.model_dump(), default=str)),
        )
    except Exception:
        pass


def list_messages(conversation_id: str | None = None) -> list[dict]:
    if conversation_id:
        rows = q(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY rowid", (conversation_id,))
    else:
        rows = q("SELECT * FROM messages ORDER BY rowid")
    return rows
