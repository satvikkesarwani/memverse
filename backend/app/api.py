"""MEMVERSE API — the only way the frontend can touch memory or the LLM.

All routes funnel through MemverseGateway. There is deliberately no
endpoint that writes/reads memory or calls the model outside the gateway.
"""
import json
import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from db import init_db, q
from gateway import MemverseGateway, list_messages
import auditlog
import receipts as receipts_mod
import policy as policy_mod
import memory as memory_store
import security_tests

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


# -------------------------------------------------------------------- demo
@app.post("/api/demo/seed")
def demo_seed():
    """Seed the demo dataset (fictional demo user 'Alex') — runs the real write pipeline."""
    result = GATEWAY.process_memory_write(
        text="My name is Alex. I'm 24 years old and I'm a computer science student from Delhi.",
        purpose="personalization", destination="assistant_context", consent=True, system=True,
    )
    GATEWAY.process_memory_write(
        text="I mostly use Python and I'm into AI and machine learning.",
        purpose="personalization", destination="assistant_context", consent=True, system=True,
    )
    GATEWAY.process_memory_write(
        text="I am looking for a software engineering internship next summer.",
        purpose="task_execution", destination="assistant_context", consent=True, system=True,
    )
    return JSONResponse(content=result.model_dump())


@app.post("/api/demo/reset")
def demo_reset():
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
        return FileResponse(idx)
    return JSONResponse({"service": "MEMVERSE Gateway API", "frontend": "run `npm run build` in /frontend"})


if os.path.isdir(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(STATIC_DIR, "assets")), name="assets")
