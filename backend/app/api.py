"""MEMVERSE API — the only way the frontend can touch memory or the LLM.

All routes funnel through MemverseGateway. There is deliberately no
endpoint that writes/reads memory or calls the model outside the gateway.
"""
import json
import os
import re
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import document_parser
import base64

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

import db
from db import init_db, q
from gateway import MemverseGateway, list_messages
import auditlog
import receipts as receipts_mod
import policy as policy_mod
import memory as memory_store
import persona as persona_mod
import security_tests
import image_scanner

app = FastAPI(title="MEMVERSE Gateway API", version="1.4.0")
_cors_origins = [o.strip() for o in os.environ.get("MEMVERSE_CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,  # set MEMVERSE_CORS_ORIGINS to a comma-separated allowlist in production
    allow_methods=["*"],
    allow_headers=["*"],
)

GATEWAY = MemverseGateway()
init_db()


# ------------------------------------------------------------------ schemas
class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=2000)
    conversation_id: str = ""
    purpose: str = "answer_query"
    destination: str = "nvidia"

    @classmethod
    def validate_prompt(cls, prompt: str) -> str:
        p = prompt.strip()
        if not p:
            raise HTTPException(422, "prompt must not be empty or whitespace-only")
        return p


class MemoryWriteRequest(BaseModel):
    text: str = Field(min_length=1, max_length=2000)
    purpose: str = "personalization"
    destination: str = "assistant_context"
    consent: bool = True
    ttl_days: int | None = None


class MemoryReadRequest(BaseModel):
    memory_id: str
    purpose: str = "answer_query"
    destination: str = "nvidia"


class RevokeRequest(BaseModel):
    memory_id: str
    reason: str = "Revoked by user"


class StatusResponse(BaseModel):
    status: str
    policy: str
    llm: str
    llm_error: str = ""
    memories: int
    events: int
    demo: bool


# -------------------------------------------------------------------- misc
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "memverse-gateway",
            "policy_version": policy_mod.ENGINE.policy["version"],
            "llm_provider": "nvidia" if os.environ.get("NVIDIA_API_KEY") else "demo"}


@app.get("/api/status", response_model=StatusResponse)
def status():
    nv_configured = bool(os.environ.get("NVIDIA_API_KEY", "").strip())
    return StatusResponse(
        status="ok",
        policy=policy_mod.ENGINE.policy["version"],
        llm="NVIDIA NIM" if nv_configured else "DEMO MODE (no NVIDIA_API_KEY)",
        llm_error="" if nv_configured else
            "Set NVIDIA_API_KEY in the server environment to enable live model calls. "
            "Demo mode is clearly labelled and deterministic.",
        memories=len(q("SELECT id FROM memories")),
        events=len(q("SELECT id FROM events")),
        demo=not nv_configured,
    )


# -------------------------------------------------------------------- chat
@app.post("/api/chat")
def chat(req: ChatRequest):
    req.prompt = ChatRequest.validate_prompt(req.prompt)
    result = GATEWAY.process_chat(
        prompt=req.prompt,
        conversation_id=req.conversation_id or None,
        purpose=req.purpose,
        destination=req.destination,
    )
    return JSONResponse(content=result.model_dump())


@app.post("/api/chat/stream")
def chat_stream(req: ChatRequest):
    req.prompt = ChatRequest.validate_prompt(req.prompt)

    def event_generator():
        for event in GATEWAY.process_chat_stream(
            prompt=req.prompt,
            conversation_id=req.conversation_id or None,
            purpose=req.purpose,
            destination=req.destination,
        ):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/documents/samples")
def document_samples():
    """List built-in sample diagnostic reports for instant demonstration."""
    samples = []
    for key, data in document_parser.SAMPLE_REPORTS.items():
        samples.append({
            "id": key,
            "title": data["title"],
            "filename": data["filename"],
            "preview": data["text"][:260] + "...",
            "char_count": len(data["text"]),
        })
    return {"samples": samples}


@app.post("/api/chat/document")
async def chat_document(
    file: UploadFile = File(None),
    sample_id: str = Form(None),
    prompt: str = Form("Please analyze and summarize this document, highlighting key information while preserving privacy."),
    conversation_id: str = Form(""),
    purpose: str = Form("document_analysis"),
    destination: str = Form("nvidia"),
):
    """Document Analysis with Zero-Trust PII Redaction."""
    doc_text = ""
    filename = "document.pdf"
    pages = 1

    if file:
        filename = file.filename
        content = await file.read()
        parsed = document_parser.parse_document_file(content, filename)
        if not parsed["success"]:
            raise HTTPException(400, parsed["error"])
        doc_text = parsed["text"]
        pages = parsed.get("pages", 1)
    elif sample_id and sample_id in document_parser.SAMPLE_REPORTS:
        sample = document_parser.SAMPLE_REPORTS[sample_id]
        doc_text = sample["text"]
        filename = sample["filename"]
    else:
        raise HTTPException(400, "Please upload a document file or select a sample report ID.")

    # Sanitize filename in prompt header so names in filenames (e.g. slice_satvik.pdf) don't leak
    clean_header_name = re.sub(r"[_\-.]+", " ", filename).strip()
    safe_filename = "document.pdf" if any(len(part) > 3 for part in clean_header_name.split()) else filename

    full_prompt = (
        f"{prompt.strip()}\n\n"
        f"--- ATTACHED DOCUMENT ({safe_filename}) ---\n"
        f"{doc_text}"
    )

    result = GATEWAY.process_chat(
        prompt=full_prompt,
        conversation_id=conversation_id or None,
        purpose=purpose,
        destination=destination,
    )

    res_dict = result.model_dump()
    res_dict["document"] = {
        "filename": filename,
        "pages": pages,
        "char_count": len(doc_text),
        "sample_id": sample_id or None,
    }
    return JSONResponse(content=res_dict)


@app.post("/api/chat/document/stream")
async def chat_document_stream(
    file: UploadFile = File(None),
    sample_id: str = Form(None),
    prompt: str = Form("Please analyze and summarize this document, highlighting key information while preserving privacy."),
    conversation_id: str = Form(""),
    purpose: str = Form("document_analysis"),
    destination: str = Form("nvidia"),
):
    """Streaming Document Analysis with Zero-Trust PII Redaction."""
    doc_text = ""
    filename = "document.pdf"
    pages = 1

    if file:
        filename = file.filename
        content = await file.read()
        parsed = document_parser.parse_document_file(content, filename)
        if not parsed["success"]:
            raise HTTPException(400, parsed["error"])
        doc_text = parsed["text"]
        pages = parsed.get("pages", 1)
    elif sample_id and sample_id in document_parser.SAMPLE_REPORTS:
        sample = document_parser.SAMPLE_REPORTS[sample_id]
        doc_text = sample["text"]
        filename = sample["filename"]
    else:
        raise HTTPException(400, "Please upload a document file or select a sample report ID.")

    # Sanitize filename in prompt header so names in filenames (e.g. slice_satvik.pdf) don't leak
    clean_header_name = re.sub(r"[_\-.]+", " ", filename).strip()
    safe_filename = "document.pdf" if any(len(part) > 3 for part in clean_header_name.split()) else filename

    full_prompt = (
        f"{prompt.strip()}\n\n"
        f"--- ATTACHED DOCUMENT ({safe_filename}) ---\n"
        f"{doc_text}"
    )

    def event_generator():
        for event in GATEWAY.process_chat_stream(
            prompt=full_prompt,
            conversation_id=conversation_id or None,
            purpose=purpose,
            destination=destination,
        ):
            if event["type"] == "done":
                event["result"]["document"] = {
                    "filename": filename,
                    "pages": pages,
                    "char_count": len(doc_text),
                    "sample_id": sample_id or None,
                }
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/chat/image")
async def chat_image(
    image: UploadFile = File(...),
    prompt: str = Form(...),
    conversation_id: str = Form(""),
    purpose: str = Form("image_generation"),
    destination: str = Form("nvidia"),
    consent_granted: str = Form("false"),
    face_detected: str = Form("false"),
    face_redacted: str = Form("false"),
):
    """Image Chat with Biometric Consent & Zero-Trust PII Stripping."""
    # Gate 1 — Consent check
    if consent_granted != "true":
        raise HTTPException(403, "Consent required — image cannot be sent without explicit consent.")

    # Read image bytes once
    content = await image.read()

    # Gate 2 — Run image_scanner validation
    scan = image_scanner.process_image_upload(content, image.filename, face_detected, consent=True)
    if not scan["success"]:
        raise HTTPException(400, scan["error"])

    # Gate 3 — Route to gateway
    # Build base64 of clean (EXIF-stripped) image
    image_b64 = scan["clean_b64"]

    result = GATEWAY.process_image_chat(
        prompt=prompt,
        image_b64=image_b64,
        image_meta={
            "filename": image.filename,
            "original_hash": scan["original_hash"],
            "clean_hash": scan["clean_hash"],
            "dimensions": scan["dimensions"],
            "face_detected": face_detected == "true",
            "face_redacted": face_redacted == "true",
            "consent_granted": consent_granted == "true",
            "purpose": purpose,
            "destination": destination,
        },
        conversation_id=conversation_id or None,
    )

    return JSONResponse(content=result.model_dump())


@app.get("/api/messages")
def messages(conversation_id: str = ""):
    return list_messages(conversation_id or None)


# ------------------------------------------------------------------- memory
@app.post("/api/memory/write")
def memory_write(req: MemoryWriteRequest):
    req.text = ChatRequest.validate_prompt(req.text)
    result = GATEWAY.process_memory_write(
        text=req.text, purpose=req.purpose, destination=req.destination,
        consent=req.consent, ttl_days=req.ttl_days,
    )
    return JSONResponse(content=result.model_dump())


@app.post("/api/memory/read")
def memory_read(req: MemoryReadRequest):
    return JSONResponse(content=GATEWAY.process_memory_read(
        req.memory_id, purpose=req.purpose, destination=req.destination))


@app.post("/api/memory/revoke")
def memory_revoke(req: RevokeRequest):
    result = GATEWAY.revoke_memory(req.memory_id, req.reason)
    return JSONResponse(content=result.model_dump())


@app.get("/api/memories")
def memories():
    out = []
    for m in memory_store.list_memories():
        d = m.model_dump()
        out.append(d)
    return {"memories": out}


@app.get("/api/memories/{memory_id}")
def memory_detail(memory_id: str):
    m = memory_store.load_memory(memory_id)
    if m is None:
        raise HTTPException(404, "memory not found")
    return m.model_dump()


# ------------------------------------------------------------ events/ledger
@app.get("/api/events")
def events(limit: int = 200):
    rows = q("SELECT * FROM events ORDER BY rowid DESC LIMIT ?", (limit,))
    return {"events": [dict(r) for r in rows]}


@app.get("/api/events/{event_id}")
def event_detail(event_id: str):
    rows = q("SELECT * FROM events WHERE id=?", (event_id,))
    if not rows:
        raise HTTPException(404, "event not found")
    return dict(rows[0])


@app.get("/api/traces/{request_id}")
def trace_detail(request_id: str):
    rows = q("SELECT * FROM traces WHERE id=?", (request_id,))
    if not rows:
        raise HTTPException(404, "trace not found")
    return json.loads(rows[0]["data_json"])


# ----------------------------------------------------------------- receipts
@app.get("/api/receipts")
def receipts_list(limit: int = 200):
    return {"receipts": receipts_mod.ledger_recent(limit)}


@app.get("/api/receipts/{receipt_id}")
def receipt_detail(receipt_id: str):
    r = receipts_mod.get_receipt(receipt_id)
    if r is None:
        raise HTTPException(404, "receipt not found")
    return r


@app.post("/api/receipts/{receipt_id}/verify")
def receipt_verify(receipt_id: str):
    return receipts_mod.verify_receipt(receipt_id)


# ------------------------------------------------------------------ policy
@app.get("/api/policies/current")
def policy_current():
    return policy_mod.ENGINE.policy


@app.post("/api/policies/update")
def policy_update(body: dict):
    """Dynamically update policy rules, field strategies, or destinations."""
    updated = policy_mod.ENGINE.update(body)
    return {"status": "updated", "policy": updated}


@app.post("/api/policies/reset")
def policy_reset():
    """Reset policy to default configuration."""
    reset = policy_mod.ENGINE.reset()
    return {"status": "reset", "policy": reset}


# ------------------------------------------------------------------- learn
@app.post("/api/learn/export")
def learn_export(body: dict = None):
    """LEARN Control Surface — evaluate stored memories for dataset export / training.

    Filters out memories where:
      - passport is REVOKED, EXPIRED, or QUARANTINED
      - consent is NOT_GRANTED for learning
      - sensitivity is HIGH or CRITICAL
    Transforms eligible memories using differential privacy / generalization.
    Generates a tamper-evident LEARN_EXPORT receipt in the ledger.
    """
    import transformer as transformer_mod
    import detector as detector_mod

    body = body or {}
    purpose = body.get("purpose", "model_finetuning")
    destination = body.get("destination", "learn_pipeline")
    epsilon = float(body.get("privacy_budget_epsilon", 0.5))

    all_memories = memory_store.list_memories()
    eligible_records = []
    excluded_records = []

    for m in all_memories:
        p = m.passport
        if not p or p.revocation_state != "ACTIVE":
            excluded_records.append({
                "memory_id": m.memory_id,
                "reason": f"Passport state '{p.revocation_state if p else 'NONE'}' — fail closed",
                "sensitivity": m.sensitivity,
            })
            continue
        if m.sensitivity in ("HIGH", "CRITICAL"):
            excluded_records.append({
                "memory_id": m.memory_id,
                "reason": f"High sensitivity ({m.sensitivity}) prohibited from learning dataset",
                "sensitivity": m.sensitivity,
            })
            continue

        entities = [detector_mod.DetectedEntity(
            entity=f.get("field", "Item"),
            value=f.get("value", ""),
            type=f.get("type", "context"),
            sensitivity=f.get("sensitivity", "LOW"),
            confidence=1.0,
            reason="Stored memory field",
        ) for f in m.payload]

        dec = policy_mod.ENGINE.evaluate(
            operation="LEARN", purpose=purpose, destination=destination,
            passport=p, poisoning_level="LOW", entities=entities,
        )

        if dec.overall == "BLOCK":
            excluded_records.append({
                "memory_id": m.memory_id,
                "reason": dec.reason,
                "sensitivity": m.sensitivity,
            })
            continue

        ctx = transformer_mod.transform_fields(dec.per_field)
        eligible_records.append({
            "memory_id": m.memory_id,
            "original_type": m.mem_type,
            "generalized_payload": [e.model_dump() for e in ctx.entries],
            "anonymized_text": ctx.assembly,
            "sensitivity": m.sensitivity,
            "noise_scale": round(1.0 / max(0.01, epsilon), 3),
        })

    evt = {
        "event_id": db.new_id("evt"),
        "event_type": "LEARN_EXPORT",
        "timestamp": db.now_iso(),
        "purpose": purpose,
        "destination": destination,
        "decision": "ALLOW" if eligible_records else "BLOCK",
        "fields_detected": len(all_memories),
        "fields_transformed": len(eligible_records),
        "policy_version": policy_mod.ENGINE.version(),
        "passport_id": "DATASET_BATCH",
        "revocation_state": "ACTIVE",
        "extra": {
            "total_candidates": len(all_memories),
            "eligible_count": len(eligible_records),
            "excluded_count": len(excluded_records),
            "privacy_budget_epsilon": epsilon,
        }
    }
    receipt = receipts_mod.create_receipt(evt)
    auditlog.receipt_created("", 0, "", 0, receipt.event_id, "LEARN_EXPORT", receipt.decision)

    return {
        "status": "success",
        "operation": "LEARN",
        "purpose": purpose,
        "destination": destination,
        "total_candidates": len(all_memories),
        "eligible_count": len(eligible_records),
        "excluded_count": len(excluded_records),
        "privacy_budget_epsilon": epsilon,
        "eligible_records": eligible_records,
        "excluded_records": excluded_records,
        "receipt": receipt.model_dump(),
    }


# ---------------------------------------------------------------- security
@app.post("/api/security/test")
def security_test(body: dict):
    name = body.get("name", "")
    result = security_tests.run_test(name, GATEWAY)
    if result is None:
        raise HTTPException(404, f"unknown test: {name}")
    return result


@app.post("/api/security/run-all")
def security_run_all():
    return {"results": security_tests.run_all(GATEWAY)}


# --------------------------------------------------------------- audit log
@app.get("/api/audit/logs")
def audit_logs(limit: int = 100):
    """Recent structured pipeline events (redacted — no prompts, no secrets)."""
    return {"logs": auditlog.recent(min(limit, 500))}


# ----------------------------------------------------------- persona vault
@app.get("/api/persona")
def get_persona():
    """Returns all persona attributes currently stored in the Global Persona Vault."""
    return {"attributes": persona_mod.get_all_persona_attributes()}


@app.delete("/api/persona/{attr_id}")
def delete_persona_attr(attr_id: str):
    """Deletes a specific persona attribute from the vault."""
    persona_mod.delete_persona_attribute(attr_id)
    return {"status": "deleted", "id": attr_id}


@app.post("/api/persona/wipe")
def wipe_persona():
    """Wipes the persona vault and resets memory store to zero clean state."""
    persona_mod.wipe_persona_vault()
    memory_store.reset_demo()
    return {"status": "wiped", "last_receipt_hash": "GENESIS"}


# -------------------------------------------------------------------- demo
@app.post("/api/demo/seed")
def demo_seed():
    """Seed the demo dataset — runs the real write pipeline."""
    result = GATEWAY.process_memory_write(
        text="My name is Alex. I'm 24 years old and I'm a computer science student from Delhi.",
        purpose="personalization", destination="assistant_context", consent=True, system=True,
    )
    return JSONResponse(content=result.model_dump())


@app.post("/api/demo/reset")
def demo_reset():
    persona_mod.wipe_persona_vault()
    memory_store.reset_demo()
    return {"status": "reset", "last_receipt_hash": "GENESIS"}


@app.post("/api/demo/seed-task")
def demo_seed_task():
    result = GATEWAY.process_memory_write(
        text="I am looking for a software engineering internship next summer.",
        purpose="task_execution", destination="assistant_context", consent=True, system=True,
    )
    return JSONResponse(content=result.model_dump())


# ------------------------------------------------------- static frontend
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")


@app.get("/")
def index():
    idx = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(idx):
        return FileResponse(
            idx,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    return JSONResponse({"service": "MEMVERSE Gateway API", "frontend": "run `npm run build` in /frontend"})


if os.path.isdir(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(STATIC_DIR, "assets")), name="assets")
    models_dir = os.path.join(STATIC_DIR, "models")
    if os.path.isdir(models_dir):
        app.mount("/models", StaticFiles(directory=models_dir), name="models")
