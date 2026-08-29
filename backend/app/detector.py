"""Sensitive-data detection.

Deterministic, rule-based detector (regex + context lexicon). Designed as a
modular interface so a Presidio-backed implementation can replace the inner
`detect_all()` function without changing the rest of the system.
"""
import re
import time
from models import DetectionResult, DetectedEntity

# ------------------------------------------------------------------ lexicon
CITIES = {
    "pune": "Western India", "mumbai": "Western India", "navi mumbai": "Western India",
    "thane": "Western India", "nashik": "Western India", "nagpur": "Western India",
    "aurangabad": "Western India", "surat": "Western India", "ahmedabad": "Western India",
    "vadodara": "Western India", "rajkot": "Western India", "goa": "Western India",
    "panaji": "Western India", "indore": "Central India", "bhopal": "Central India",
    "delhi": "Northern India", "new delhi": "Northern India", "noida": "Northern India",
    "ghaziabad": "Northern India", "gurugram": "Northern India", "gurgaon": "Northern India",
    "meerut": "Northern India", "lucknow": "Northern India", "kanpur": "Northern India",
    "agra": "Northern India", "varanasi": "Northern India", "jaipur": "Northern India",
    "udaipur": "Northern India", "jodhpur": "Northern India", "chandigarh": "Northern India",
    "amritsar": "Northern India", "dehradun": "Northern India", "shimla": "Northern India",
    "jammu": "Northern India", "srinagar": "Northern India", "patna": "Eastern India",
    "ranchi": "Eastern India", "kolkata": "Eastern India", "bhubaneswar": "Eastern India",
    "guwahati": "Eastern India", "jamshedpur": "Eastern India", "cuttack": "Eastern India",
    "bengaluru": "Southern India", "bangalore": "Southern India", "mysuru": "Southern India",
    "mysore": "Southern India", "chennai": "Southern India", "hyderabad": "Southern India",
    "secunderabad": "Southern India", "kochi": "Southern India", "cochin": "Southern India",
    "thiruvananthapuram": "Southern India", "trivandrum": "Southern India",
    "coimbatore": "Southern India", "madurai": "Southern India", "vijayawada": "Southern India",
    "visakhapatnam": "Southern India", "mangaluru": "Southern India", "mangalore": "Southern India",
}

HEALTH_TERMS = [
    "diabetes", "blood pressure", "bp ", "hypertension", "allergy", "allergic",
    "asthma", "medication", "medicine", "prescription", "diagnosed", "disease",
    "depression", "anxiety", "therapy", "surgery", "cancer", "migraine",
    "insomnia", "cardiac", "heart condition", "covid", "fever", "infection",
    "chronic pain", "psychiatrist", "psychologist", "counseling", "hiv",
    "thyroid", "cholesterol", "vaccination", "vaccine",
]

FINANCIAL_TERMS = [
    "salary", "income", "bank account", "account number", "acc no", "credit card",
    "debit card", "card number", "upi", "pan card", "aadhaar", "aadhar",
    "cvv", "net worth", "monthly earning", "savings", "loan amount", "emi",
    "mutual fund", "stock portfolio", "investment",
]

EDUCATION_TERMS = [
    "student", "studying", "study", "computer science", "engineering", "b.tech",
    "btech", "b.e", "m.tech", "degree", "university", "college", "school",
    "class 12", "class 10", "semester", "sem ", "graduate", "undergraduate",
    "postgraduate", "enrolled", "internship", "course", "major",
]

# ------------------------------------------------------------------ patterns
PATTERNS = [
    # (type, sensitivity, regex, reason, confidence)
    ("email", "HIGH",
     r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
     "Email address detected.", 0.98),
    ("phone", "HIGH",
     r"(?:\+?91[-.\s]?)?[6-9]\d{9}\b",
     "Mobile number pattern detected.", 0.9),
    ("phone", "HIGH",
     r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
     "Phone number pattern detected.", 0.75),
    ("credential", "CRITICAL",
     r"\b(?:sk|pk|rk|ghp)[_-][A-Za-z0-9]{16,}\b",
     "API key / secret token pattern detected.", 0.99),
    ("credential", "CRITICAL",
     r"\b(?:password|passwd|pwd|pin|otp)\s*(?:is|[:=])\s*['\"]?([A-Za-z0-9@#$%^&*!?._-]{4,})['\"]?\b",
     "Credential (password/PIN/OTP) disclosed.", 0.95),
    ("credential", "CRITICAL",
     r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
     "Long base64-like secret detected.", 0.6),
    ("financial", "HIGH",
     r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
     "Card number pattern (13-16 digits) detected.", 0.92),
    ("financial", "HIGH",
     r"\b\d{9,18}\b(?=.*\b(?:account|acct|bank|card|upi|ifsc)\b)",
     "Account identifier pattern detected near banking context.", 0.8),
]

NAME_STOPWORDS = {
    "from", "in", "at", "for", "to", "with", "into", "about", "on", "here",
    "there", "going", "trying", "looking", "working", "studying", "waiting",
    "feeling", "learning", "reading", "playing", "planning", "currently",
    "very", "so", "just", "really", "also", "now", "not", "a", "an", "the",
    "born", "based", "living", "staying", "residing", "located", "currently",
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
    "ten", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty",
    "ninety", "hundred", "this", "that", "these", "those", "my", "your", "his",
    "her", "our", "their", "am", "is", "are", "was", "were", "will", "shall",
    "can", "could", "would", "should", "may", "might", "must", "have", "has",
    "had", "do", "does", "did", "been", "being", "be", "by", "as", "of", "or",
    "and", "but", "if", "then", "than", "when", "where", "who", "whom",
    "which", "what", "why", "how", "any", "some", "all", "each", "every",
    "both", "either", "neither", "such", "only", "own", "same", "other",
    "another", "new", "old", "first", "last", "next", "few", "many", "much",
    "more", "most", "little", "less", "least",
}

CONTEXT_PATTERNS = [
    # name
    ("identity", "Name", "HIGH",
     r"\b(?:my name is|i am called|you can call me|call me)\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,2})",
     "Identity — personal name disclosed.", 0.97),
    ("identity", "Name", "HIGH",
     r"\b(?:i'?m|i am)\s+([A-Z][a-z]{2,})\b(?!\s+(?:a|an|the|not|from|in|at|for|to|with|into|about|on|here|there|going|trying|looking|working|studying|waiting|feeling|learning|reading|playing|planning|currently|very|so|just|really|also|now|born|based|living|staying|residing|located)\b)",
     "Identity — first name disclosed.", 0.85),
    # age
    ("demographic", "Age", "MEDIUM",
     r"\b(?:i am|i'?m|age is|aged|turned)\s*(?:just\s*)?(\d{1,3})\s*(?:years?\s*old|years?|yrs?|yo)?\b",
     "Age disclosed.", 0.9),
    ("demographic", "Age", "MEDIUM",
     r"\b(?:age|aged)\s*[:=]?\s*(\d{1,3})\b",
     "Age disclosed.", 0.88),
    ("demographic", "Age", "MEDIUM",
     r"\b(\d{1,3})\s*years?\s*old\b",
     "Age disclosed.", 0.92),
    # location
    ("location", "Location", "MEDIUM",
     r"\b(?:i (?:live|stay|am based|reside)|living|staying|based|located|from|in)\s+(?:in|at)?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?)\b",
     "Location mentioned.", 0.7),
    ("location", "Location", "MEDIUM",
     r"\b(?:my (?:city|hometown|home town|native place)|city is|hometown is)\s+is?\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?)",
     "Location mentioned.", 0.8),
]

HEALTH_RE = re.compile(
    r"\b(" + "|".join(re.escape(t.strip()) for t in HEALTH_TERMS) + r")\b", re.I)
FIN_RE = re.compile(
    r"\b(" + "|".join(re.escape(t.strip()) for t in FINANCIAL_TERMS) + r")\b", re.I)
EDU_RE = re.compile(
    r"\b(" + "|".join(re.escape(t.strip()) for t in EDUCATION_TERMS) + r")\b", re.I)


def _dedupe(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    seen = set()
    out = []
    for e in entities:
        key = (e.type, e.value.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def _city(value: str) -> str | None:
    v = value.strip().lower().rstrip(".,!?")
    if v in CITIES:
        return v
    return None


def detect_all(text: str, source: str = "user_prompt") -> DetectionResult:
    """Main detection entry point — deterministic."""
    t0 = time.perf_counter()
    entities: list[DetectedEntity] = []
    if not text:
        return DetectionResult(source=source, ms=(time.perf_counter() - t0) * 1000)

    lower = text.lower()

    # --- generic patterns
    for typ, sens, rx, reason, conf in PATTERNS:
        for m in re.finditer(rx, text, re.I):
            entities.append(DetectedEntity(
                entity=typ.title(), value=m.group(0), type=typ, sensitivity=sens,
                reason=reason, confidence=conf,
                context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
            ))

    # --- contextual patterns (names, ages, locations)
    for typ, entity, sens, rx, reason, conf in CONTEXT_PATTERNS:
        for m in re.finditer(rx, text, re.I):
            val = m.group(1).strip(" .,!?")
            if not val:
                continue
            if typ == "location":
                city = _city(val)
                if city is None:
                    continue
                val = city.title()
            if typ == "identity" and (len(val) < 2 or val.lower() in NAME_STOPWORDS):
                continue
            entities.append(DetectedEntity(
                entity=entity, value=val, type=typ, sensitivity=sens,
                reason=reason, confidence=conf,
                context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
            ))

    # --- age near-context ("I am 22" without "years")
    for m in re.finditer(r"\b(?:i am|i'?m)\s+(\d{1,3})\b(?!\s*%)", text, re.I):
        val = int(m.group(1))
        if 10 <= val <= 110:
            entities.append(DetectedEntity(
                entity="Age", value=str(val), type="demographic", sensitivity="MEDIUM",
                reason="Age disclosed.", confidence=0.8,
                context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
            ))

    # --- health / financial / education lexicons
    for m in HEALTH_RE.finditer(lower):
        entities.append(DetectedEntity(
            entity="Health", value=m.group(1).strip(), type="health", sensitivity="CRITICAL",
            reason="Health-related information disclosed.", confidence=0.85,
            context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
        ))
    for m in FIN_RE.finditer(lower):
        entities.append(DetectedEntity(
            entity="Financial", value=m.group(1).strip(), type="financial", sensitivity="HIGH",
            reason="Financial information disclosed.", confidence=0.85,
            context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
        ))
    for m in EDU_RE.finditer(lower):
        entities.append(DetectedEntity(
            entity="Education", value=m.group(1).strip(), type="education", sensitivity="LOW",
            reason="Educational detail disclosed.", confidence=0.8,
            context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
        ))

    return DetectionResult(
        source=source,
        entities=_dedupe(entities),
        ms=(time.perf_counter() - t0) * 1000,
    )

