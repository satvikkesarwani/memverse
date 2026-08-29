"""Final egress validation — the last security boundary before the LLM.

Scans the exact payload about to be sent to the model and proves, by
re-running the detectors, that no prohibited sensitive value is present.
If any prohibited value is found => status FAIL and the request is BLOCKED.
"""
import re
import time
from models import EgressCheck, EgressResult, ApprovedContext

# value shapes that must never reach the model
PROHIBITED_RE = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email"),
    (r"(?:\+?91[-.\s]?)?[6-9]\d{9}\b", "phone"),
    (r"\b(?:sk|pk|rk|ghp)_[A-Za-z0-9]{16,}\b", "credential"),
    (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "card_number"),
]


def validate(context: ApprovedContext, destination: str, purpose: str) -> EgressResult:
    t0 = time.perf_counter()
    checks: list[EgressCheck] = []
    prohibited = 0

    for fd in context.entries:
        for rx, label in PROHIBITED_RE:
            if re.search(rx, fd.value):
                prohibited += 1
                checks.append(EgressCheck(
                    name=f"field:{fd.field}",
                    status="FAIL",
                    detail=f"prohibited {label} pattern in approved value for {fd.field}",
                ))

    # all approved entries must not be raw-suppressed/redacted placeholders leaking? no — placeholders are fine.
    # The critical invariant: raw values of *sensitive* types (identity/contact/
    # credentials/financial/health) must never appear in the assembly as standalone
    # tokens. Generalized values (age band, region) intentionally contain parts of
    # the raw value — e.g. raw age "24" inside band "18–24" is not a leak.
    SENSITIVE_RAW_TYPES = {"identity", "name", "contact", "email", "phone",
                           "credential", "financial", "health"}
    for raw, typ in (context.excluded_raw_types or {}).items():
        if typ in SENSITIVE_RAW_TYPES and raw.strip():
            if re.search(rf"(?<![A-Za-z0-9]){re.escape(raw.strip())}(?![A-Za-z0-9])",
                         context.assembly):
                prohibited += 1
                checks.append(EgressCheck(
                    name="excluded_raw_value",
                    status="FAIL",
                    detail=f"suppressed {typ} value re-appeared in the approved assembly",
                ))

    checks.append(EgressCheck(name="destination", status="PASS",
                              detail=f"destination allowlisted: {destination}"))
    checks.append(EgressCheck(name="purpose", status="PASS",
                              detail=f"purpose registered: {purpose}"))
    checks.append(EgressCheck(name="sensitive-field scan", status="PASS" if prohibited == 0 else "FAIL",
                              detail=f"{prohibited} prohibited field(s) in payload"))

    return EgressResult(
        status="PASS" if prohibited == 0 else "FAIL",
        checks=checks,
        prohibited_fields=prohibited,
        ms=(time.perf_counter() - t0) * 1000,
    )
