"""Field-level transformation engine for MEMVERSE.

Deterministic transforms, applied field-by-field:
  ALLOW      -> keep value as-is
  SUPPRESS   -> generic placeholder by type (identity => "person")
  GENERALIZE -> coarser representation (age band, region, education band, org band)
  REDACT     -> [REDACTED]
  TOKENIZE   -> persistent opaque token (local mapping table)
"""
import re
import time
from models import ApprovedContext, ApprovedContextEntry

AGE_BANDS = [
    (13, 17, "13–17"), (18, 24, "18–24"), (25, 29, "25–29"),
    (30, 39, "30–39"), (40, 49, "40–49"), (50, 59, "50–59"),
    (60, 200, "60+"),
]

SUPPRESS_PLACEHOLDERS = {
    "identity": "person",
    "name": "person",
    "contact": "[contact hidden]",
    "credential": "[credential hidden]",
    "financial": "[financial info hidden]",
    "health": "[health info hidden]",
    "organization": "[organization hidden]",
}

GENERALIZERS = {
    "age": lambda v: age_band(v),
    "demographic": lambda v: age_band(v),
    "location": lambda v: location_region(v),
    "city": lambda v: location_region(v),
    "education": lambda v: education_band(v),
    "organization": lambda v: organization_band(v),
}


def age_band(raw: str) -> str:
    try:
        n = int(re_digits(raw))
    except Exception:
        return "adult"
    for lo, hi, label in AGE_BANDS:
        if lo <= n <= hi:
            return label
    return "adult"


def re_digits(v: str) -> str:
    m = re.search(r"\d+", v)
    return m.group(0) if m else "0"


def location_region(location_text: str) -> str:
    from detector import CITIES
    low = location_text.strip().lower()
    
    # 1. Direct city match
    if low in CITIES:
        return f"{CITIES[low]}"
    
    # 2. Check if a known city is contained inside compound address (e.g. "Sector 137, Noida")
    for city_name, reg in sorted(CITIES.items(), key=lambda x: len(x[0]), reverse=True):
        if city_name in low:
            return f"{city_name.title()} ({reg})"
            
    # 3. Sector / Street without city
    if any(k in low for k in ("sector", "sec ", "phase", "plot", "street", "road", "block", "pincode", "pin")):
        return "Local Sector/Area (India)"
        
    return "India"


def region(city: str) -> str:
    """Backwards-compatible alias for location_region."""
    return location_region(city)


def education_band(v: str) -> str:
    low = v.lower()
    if any(k in low for k in ("phd", "ph.d", "doctorate", "m.tech", "m.tech", "masters", "postgraduate", "pg ")):
        return "postgraduate"
    if any(k in low for k in ("b.tech", "btech", "b.e", "bachelor", "engineering", "degree", "undergraduate", "cs student", "computer science")):
        return "graduate/undergraduate"
    if any(k in low for k in ("12", "class 12", "higher secondary", "intermediate")):
        return "higher-secondary"
    if any(k in low for k in ("10", "class 10", "secondary")):
        return "secondary"
    if any(k in low for k in ("student", "school", "college")):
        return "student"
    return "education"


def organization_band(v: str) -> str:
    low = v.lower()
    if any(k in low for k in ("iit", "iiit", "nit", "bits", "davv", "university", "college", "institute")):
        return "Higher Education Institution"
    if any(k in low for k in ("google", "microsoft", "amazon", "apple", "meta", "nvidia", "tcs", "infosys", "wipro", "accenture", "cognizant", "deloitte")):
        return "Enterprise Technology Organization"
    return "Organization"


def transform_fields(fields: list, tokenizer=None) -> ApprovedContext:
    """fields: list of FieldDecision (already policy-resolved)."""
    t0 = time.perf_counter()
    entries: list[ApprovedContextEntry] = []
    excluded: list[str] = []
    excluded_types: dict = {}

    for fd in fields:
        action = fd.action
        raw = fd.raw_value
        if action == "ALLOW":
            val = raw
        elif action == "SUPPRESS":
            val = SUPPRESS_PLACEHOLDERS.get(fd.type, "[hidden]")
            excluded.append(raw)
            excluded_types[raw] = fd.type
        elif action == "GENERALIZE":
            g = GENERALIZERS.get(fd.type) or GENERALIZERS.get(fd.field.lower())
            val = g(raw) if g else f"{raw} (approx.)"
            excluded.append(raw)
            excluded_types[raw] = fd.type
        elif action == "REDACT":
            val = "[REDACTED]"
            excluded.append(raw)
            excluded_types[raw] = fd.type
        elif action == "TOKENIZE":
            if tokenizer is not None:
                val = tokenizer.tokenize(raw)
            else:
                val = f"tok_{hash(raw) & 0xffffffff:08x}"
            excluded.append(raw)
            excluded_types[raw] = fd.type
        else:  # BLOCK
            fd.output = "[BLOCKED]"
            continue  # field not allowed to leave at all

        fd.output = val
        entries.append(ApprovedContextEntry(
            field=fd.field, type=fd.type, value=val, sensitivity=fd.sensitivity,
        ))

    # deterministic assembly (stable order, same-field values merged)
    merged: dict[tuple, list] = {}
    for e in entries:
        merged.setdefault((e.type, e.field), []).append(e.value)
    parts = []
    for (typ, field), values in sorted(merged.items()):
        parts.append(f"{field}: {'; '.join(dict.fromkeys(values))}")
    assembly = "\n".join(parts)

    return ApprovedContext(
        entries=entries,
        excluded_raw_values=excluded,
        excluded_raw_types=excluded_types,
        assembly=assembly,
        ms=(time.perf_counter() - t0) * 1000,
    )
