"""LLM provider abstraction.

- NVIDIAProvider: real HTTPS call to the NVIDIA NIM API using
  NVIDIA_API_KEY from the environment. Key never touches the frontend.
- DemoProvider: deterministic template responder, ONLY used when no
  NVIDIA_API_KEY is configured. Every demo response is explicitly labelled.
"""
import os
import time
import urllib.error
import urllib.request
import json as _json
from dotenv import load_dotenv

# Load backend/.env (NVIDIA_API_KEY, NVIDIA_BASE_URL, ...) if present.
# The key is read server-side only and never reaches the frontend.
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

import auditlog

NVIDIA_URL = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1/chat/completions")
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
NVIDIA_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()


class LLMProvider:
    name = "abstract"
    model = ""

    def generate(self, messages: list[dict], purpose: str = "", request_id: str = "", request_number: int = 0) -> dict:
        raise NotImplementedError

    def generate_stream(self, messages: list[dict], purpose: str = "", request_id: str = "", request_number: int = 0):
        raise NotImplementedError


class NVIDIAProvider(LLMProvider):
    name = "nvidia"
    model = NVIDIA_MODEL

    def generate_stream(self, messages: list[dict], purpose: str = "", request_id: str = "", request_number: int = 0):
        t0 = time.perf_counter()
        if not NVIDIA_KEY:
            raise RuntimeError("NVIDIA_API_KEY is not configured")
        body = _json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": 1024,
            "temperature": 0.6,
            "top_p": 0.9,
            "stream": True,
            "chat_template_kwargs": {"enable_thinking": False},
        }).encode("utf-8")
        req = urllib.request.Request(
            NVIDIA_URL, data=body, method="POST",
            headers={"Authorization": f"Bearer {NVIDIA_KEY}",
                     "Content-Type": "application/json",
                     "Accept": "text/event-stream"},
        )
        auditlog.model_request_sent(request_id, request_number, "", 0, self.name, self.model, 0)
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                in_think = False
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        chunk = _json.loads(payload)
                        delta = chunk["choices"][0].get("delta", {})
                        piece = delta.get("content") or ""
                        if piece:
                            if "<think>" in piece:
                                in_think = True
                                continue
                            if "</think>" in piece:
                                in_think = False
                                piece = piece.split("</think>", 1)[1]
                            if not in_think and piece:
                                yield piece
                    except Exception:
                        continue
        except urllib.error.HTTPError as e:
            auditlog.model_request_failed(request_id, request_number, "", 0, f"http_{e.code}")
            raise RuntimeError(f"NVIDIA API HTTP {e.code}: {e.read().decode('utf-8', 'ignore')[:300]}")
        except Exception as e:
            auditlog.model_request_failed(request_id, request_number, "", 0, "network")
            raise RuntimeError(f"NVIDIA connection failed: {e}")
        auditlog.model_response_received(request_id, request_number, "", 0, self.name,
                                         (time.perf_counter() - t0) * 1000)

    def generate(self, messages: list[dict], purpose: str = "", request_id: str = "", request_number: int = 0) -> dict:
        t0 = time.perf_counter()
        pieces = []
        for piece in self.generate_stream(messages, purpose=purpose, request_id=request_id, request_number=request_number):
            pieces.append(piece)
        text = "".join(pieces).strip()
        return {
            "text": text,
            "provider": self.name,
            "model": self.model,
            "latency_ms": (time.perf_counter() - t0) * 1000,
            "demo": False,
            "error": "",
        }


class DemoProvider(LLMProvider):
    """Deterministic demo responder — never claims to be a real model."""
    name = "demo"
    model = "memverse-demo-v1"

    def generate_stream(self, messages: list[dict], purpose: str = "", request_id: str = "", request_number: int = 0):
        t0 = time.perf_counter()
        user = messages[-1]["content"] if messages else ""
        ctx = ""
        for m in messages:
            if m["role"] == "system":
                ctx = m["content"]
        text = self._respond(user, ctx)
        auditlog.model_request_sent(request_id, request_number, "", 0, self.name, self.model, 0)
        words = text.split(" ")
        for i, w in enumerate(words):
            yield (w if i == 0 else " " + w)
            time.sleep(0.015)
        auditlog.model_response_received(request_id, request_number, "", 0, self.name,
                                         (time.perf_counter() - t0) * 1000)

    def generate(self, messages: list[dict], purpose: str = "", request_id: str = "", request_number: int = 0) -> dict:
        t0 = time.perf_counter()
        user = messages[-1]["content"] if messages else ""
        ctx = ""
        for m in messages:
            if m["role"] == "system":
                ctx = m["content"]
        time.sleep(0.1)
        text = self._respond(user, ctx)
        auditlog.model_request_sent(request_id, request_number, "", 0, self.name, self.model, 0)
        auditlog.model_response_received(request_id, request_number, "", 0, self.name,
                                         (time.perf_counter() - t0) * 1000)
        return {
            "text": text,
            "provider": self.name,
            "model": self.model,
            "latency_ms": (time.perf_counter() - t0) * 1000,
            "demo": True,
            "error": "",
        }

    def _respond(self, user: str, ctx: str) -> str:
        u = user.lower()

        def ctx_field(label: str) -> str:
            for line in (ctx or "").splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    if k.strip().lower() == label.lower():
                        return v.strip()
            return ""

        name = ctx_field("Name") or ctx_field("name")
        age = ctx_field("Age") or ctx_field("age")
        region = ctx_field("Location") or ctx_field("City") or ctx_field("Region")
        task = ctx_field("Task") or ctx_field("task")
        context_line = ctx_field("Context") or ctx_field("context")

        if any(k in u for k in ("programming language", "language do i use", "which language", "code in", "coding language")):
            if context_line:
                return (f"From your approved memory profile: {context_line}. "
                        "That detail was ALLOWED by policy — it's not identity-sensitive.")
            return "I don't have a memory about your programming stack yet. Tell me, e.g. \"I mostly use Python\", and MEMVERSE will store it."
        if "what do you remember" in u or "what do you know about me" in u or "tell me something you know" in u or "about me" in u and "?" in u:
            if not ctx:
                return "I don't have any approved memories about you yet."
            lines = [l.strip() for l in (ctx or "").splitlines() if l.strip()]
            return "Here's what MEMVERSE approved for me to know:\n\n" + "\n".join(f"• {l}" for l in lines) + \
                   "\n\nExact identity details stay in your private memory vault — I only get the policy-approved view."
        if any(k in u for k in ("name and age", "age and name", "name & age")):
            if not ctx:
                return "I don't have a stored memory about that yet. Tell me something about yourself and I'll remember it — under MEMVERSE protection, of course."
            bits = []
            if age:
                bits.append(f"your age band is {age}")
            if region:
                bits.append(f"you're from {region}")
            detail = " and ".join(bits) if bits else "a MEMVERSE-approved profile"
            return (f"Based on your approved memory profile: {detail} — and that's exactly the level of detail "
                    f"MEMVERSE permits me to use. Your exact name and age stay in your private memory vault; "
                    f"I only receive what the policy allows.")
        if "name" in u and ("my" in u or "what" in u or "who" in u):
            if not ctx:
                return "I don't have your name in memory yet. You can tell me, e.g. \"My name is …\", and MEMVERSE will store it with a passport."
            if name and name.lower() not in ("person", "[hidden]", "unknown"):
                return f"Your stored profile says your name is {name}."
            return ("I can't see your exact name — MEMVERSE policy suppressed it for this request. "
                    "Your identity stays in your local memory vault.")
        if "age" in u and ("my" in u or "what" in u or "how old" in u):
            if not ctx:
                return "I don't have your age in memory yet."
            if age and age not in ("adult", "[REDACTED]"):
                return f"Your profile shows an age band of {age} — your exact age is generalized by MEMVERSE policy."
            return "Your exact age was generalized by MEMVERSE before reaching me."
        if "where" in u and any(k in u for k in ("live", "from", "city", "located", "place")):
            if region and region != "India":
                return f"Your profile places you in {region}."
            return "I don't have a stored location for you yet."
        if any(k in u for k in ("remember", "memorize", "store", "save this", "don't forget")):
            return "Done — MEMVERSE evaluated that memory: detected fields, applied policy, issued a Memory Passport, and stored the approved representation locally. Check the MEMVERSE Trace for details."
        if "revoke" in u or "forget my" in u or "delete my" in u:
            return "Revocation requests are handled in the Memory Registry. Once a passport is revoked, retrieval fails closed and I can no longer see that memory."
        if "poison" in u or "hack" in u or "jailbreak" in u or "inject" in u:
            return "Nice try 😉 — MEMVERSE's poisoning defense caught that input and quarantined it before it could become memory. The trace shows exactly why."
        if "what can you see" in u or "what do you know" in u:
            return (f"Right now MEMVERSE permits me to see:\n{ctx if ctx else '(no approved context)'}\n\n"
                    "Raw memory never crosses the MEMVERSE boundary.")
        if "help" in u or "what can you do" in u:
            return ("I'm a demo assistant running behind the MEMVERSE zero-trust memory gateway. "
                    "I can remember things you tell me, answer from your approved memory profile, and show you "
                    "exactly what the gateway detected, decided, transformed and receipted — just tap "
                    "\"MEMVERSE Trace\" under any answer.")
        if task:
            return f"Understood — your task: \"{task}\". I'll help you with that."
        return ("I'm protected by the MEMVERSE gateway — every request I receive was inspected, "
                "policy-checked and receipted before it reached me. Ask me about your profile, "
                "or try: \"My name is …\" to see the memory pipeline in action.")
