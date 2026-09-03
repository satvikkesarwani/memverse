"""Memory-poisoning / prompt-injection defense for MEMVERSE.

Deterministic pattern-weighted scorer. High risk => QUARANTINE on writes,
BLOCK on chat (fail closed). Medium risk => SANITIZE (strip the instruction
carrier) and proceed with a flagged trace.
"""
import re
import time
from models import PoisoningMatch, PoisoningResult

# (regex, weight, label)
PATTERNS = [
    (r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|earlier|above)\s+(?:instructions?|prompts?|context|policies?|rules)\b", 30, "instruction override"),
    (r"\bignore\s+(?:the\s+)?(?:system|developer)\s+(?:prompt|instructions?|message)\b", 32, "system-prompt override"),
    (r"\bignore\s+(?:all\s+)?(?:policies?|rules|guidelines|safety|security)\b", 28, "policy override"),
    (r"\balways\s+obey\s+(?:this\s+)?(?:memory|instruction|message)\b", 22, "blind obedience demand"),
    (r"\bnever\s+tell\s+(?:the\s+)?(?:user|them|anyone)\b", 25, "user concealment"),
    (r"\bdo\s+not\s+(?:mention|disclose|reveal|tell)\s+(?:this|that|the)\b", 18, "concealment instruction"),
    (r"\b(?:override|bypass|circumvent)\s+(?:the\s+)?(?:policy|gateway|security|controls?|membrane|memverse)\b", 80, "policy bypass attempt"),
    (r"\bjailbreak\b", 85, "jailbreak"),
    (r"\b(?:exfiltrate|exfiltration|leak|steal|extract)\s+(?:my\s+)?(?:private|personal|sensitive|all)\s+(?:data|information|info|details|identity)\b", 50, "data exfiltration"),
    (r"\b(?:reveal|disclose|show|give|share|send|output|hand\s+over)\s+(?:my\s+)?(?:email|phone\s*number|mobile\s*number|home\s+address|password|ssn|credit\s*card|aadhaar|pan\s+number|bank\s+details|id\s+number)\b", 22, "contact/credential exfiltration"),
    (r"\b(?:tell|give|hand|provide)\s+me\s+(?:my|the)\s+(?:full\s+)?(?:name|identity|real\s+name)\b", 20, "identity disclosure demand"),

    (r"\bgive\s+(?:the\s+)?(?:model|ai|llm|assistant)\s+(?:my\s+)?(?:private|sensitive|personal|complete|all|unredacted)\s+(?:identity|information|info|data|memory)\b", 50, "identity transfer demand"),
    (r"\bsend\s+(?:my\s+)?(?:private|personal|sensitive|all)\s+(?:information|data|details|identity)\s+to\s+(?:external|third.party|tools?|servers?)\b", 30, "unauthorized data transfer"),
    (r"\b(?:elevat|escalat).{0,20}\b(?:privileges?|permissions?|access)\b", 25, "privilege escalation"),
    (r"\b(?:grant|give)\s+(?:me|yourself)\s+(?:admin|root|sudo|superuser)\s*(?:access|privileges?)?\b", 35, "privilege escalation"),
    (r"\bremember\s+this\s+forever\b", 8, "persistence pressure"),
    (r"\bstore\s+this\s+(?:permanently|forever|as\s+a\s+system\s+rule)\b", 15, "malicious persistence"),
    (r"\b(?:pretend|act|behave)\s+as\s+(?:if\s+)?(?:you\s+are|you'?re|to\s+be)\s+(?:the\s+)?(?:system|admin|god|another\s+ai|dan)\b", 25, "role impersonation"),
    (r"\b(?:reveal|disclose|show|give|share|output|retrieve|display|dump)\s+(?:my\s+|the\s+)?(?:complete|full|entire|all|raw)\s+(?:memory|memories|private\s+information|sensitive\s+information|data|information|details|context)\b", 50, "complete memory extraction"),
    (r"\b\*\*(?:system|developer|assistant)\s*(?:instructions?|prompt)?\*\*\b", 20, "hidden system instruction injection"),
    (r"\boutput\s+(?:your\s+)?(?:system|developer)\s+prompt\b", 35, "prompt extraction"),
    (r"\b(?:print|show|repeat|reveal|display)\s+(?:your\s+|the\s+)?(?:full\s+)?(?:system|developer)\s+(?:prompt|instructions?)\b", 35, "system prompt extraction"),
    (r"\b(?:print|show|repeat|reveal)\s+(?:your\s+)?(?:hidden|internal)\s+(?:instructions?|prompt|chain.of.thought)\b", 35, "hidden instruction extraction"),
    (r"\b(?:run|execute)\s+(?:a\s+|an\s+)?(?:shell|terminal|command|curl|wget|bash|python|script)\b", 35, "unauthorized command execution"),
    (r"\b(?:download|install)\s+(?:and\s+)?(?:run|execute)\b", 25, "malicious payload installation"),
    (r"\bdon'?t\s+(?:follow|obey|listen\s+to)\s+(?:the\s+)?(?:policy|rules|gateway|memverse)\b", 30, "policy defiance"),
    (r"\bignore\s+everything\s+(?:above|before|previously)\b", 30, "context wipe instruction"),
    (r"\b(?:new\s+)?(?:system\s+|developer\s+)?instructions?\s*:\s*(?:you\s+are|you'?re)\b", 20, "forged system instruction"),
    (r"\b(?:you\s+are\s+)?(?:now\s+)?(?:unrestricted|unbound|ungoverned)\b", 35, "constraint removal"),
]

MAX_SCORE = 100


def analyze(text: str) -> PoisoningResult:
    t0 = time.perf_counter()
    matches: list[PoisoningMatch] = []
    if not text:
        return PoisoningResult(ms=(time.perf_counter() - t0) * 1000)

    score = 0
    for rx, weight, label in PATTERNS:
        m = re.search(rx, text, re.I)
        if m:
            matches.append(PoisoningMatch(
                pattern=label, weight=weight,
                matched_text=m.group(0)[:80],
            ))
            score += weight

    if len(matches) >= 2:
        score += 15  # stacked-attack escalation: multiple distinct signals

    if score >= 80:
        level, action = "CRITICAL", "BLOCK"
    elif score >= 50:
        level, action = "HIGH", "QUARANTINE"
    elif score >= 20:
        level, action = "MEDIUM", "SANITIZE"
    else:
        level, action = "LOW", "ALLOW"

    score = min(MAX_SCORE, score)
    if matches:
        top = matches[0]
        reason = (
            f"Memory contains suspicious pattern: '{top.matched_text}' "
            f"({top.pattern}). Matched {len(matches)} pattern(s), total weight {score}."
        )
    else:
        reason = "No suspicious patterns detected."

    return PoisoningResult(
        risk_score=score, risk_level=level, matched_patterns=matches,
        reason=reason, action=action, ms=(time.perf_counter() - t0) * 1000,
    )


INSTRUCTION_CARRIER = re.compile(
    r"(?i)\b(?:remember\s+this\s*(?:forever|instruction|rule)?[^.!?\n]*[.!?]?|"
    r"ignore[^.!?\n]*[.!?]?|always\s+obey[^.!?\n]*[.!?]?|never\s+tell[^.!?\n]*[.!?]?|"
    r"you\s+must[^.!?\n]*[.!?]?|do\s+not\s+mention[^.!?\n]*[.!?]?)"
)


def sanitize_text(text: str) -> str:
    """Strip instruction carriers while preserving factual context."""
    cleaned = INSTRUCTION_CARRIER.sub("", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned if cleaned else text


sanitize = sanitize_text
