"""Sensitive-data detection for MEMVERSE.

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
    "greater noida": "Northern India", "ghaziabad": "Northern India", "gurugram": "Northern India",
    "gurgaon": "Northern India", "faridabad": "Northern India", "meerut": "Northern India",
    "lucknow": "Northern India", "kanpur": "Northern India", "agra": "Northern India",
    "varanasi": "Northern India", "jaipur": "Northern India", "udaipur": "Northern India",
    "jodhpur": "Northern India", "chandigarh": "Northern India", "amritsar": "Northern India",
    "dehradun": "Northern India", "shimla": "Northern India", "jammu": "Northern India",
    "srinagar": "Northern India", "patna": "Eastern India", "ranchi": "Eastern India",
    "kolkata": "Eastern India", "bhubaneswar": "Eastern India", "guwahati": "Eastern India",
    "jamshedpur": "Eastern India", "cuttack": "Eastern India", "bengaluru": "Southern India",
    "bangalore": "Southern India", "mysuru": "Southern India", "mysore": "Southern India",
    "chennai": "Southern India", "hyderabad": "Southern India", "secunderabad": "Southern India",
    "kochi": "Southern India", "cochin": "Southern India", "thiruvananthapuram": "Southern India",
    "trivandrum": "Southern India", "coimbatore": "Southern India", "madurai": "Southern India",
    "vijayawada": "Southern India", "visakhapatnam": "Southern India", "mangaluru": "Southern India",
    "mangalore": "Southern India",
}

HEALTH_TERMS = [
    "diabetes", "blood pressure", "bp ", "hypertension", "allergy", "allergic",
    "asthma", "medication", "medicine", "prescription", "diagnosed", "disease",
    "depression", "anxiety", "therapy", "surgery", "cancer", "migraine",
    "insomnia", "cardiac", "heart condition", "covid", "fever", "infection",
    "chronic pain", "psychiatrist", "psychologist", "counseling", "hiv",
    "thyroid", "cholesterol", "vaccination", "vaccine", "insulin", "metformin",
    "paracetamol", "aspirin", "atorvastatin", "amoxicillin", "ibuprofen", "omeprazole",
    "losartan", "cetirizine", "pantoprazole", "azithromycin",
]

FINANCIAL_TERMS = [
    "salary", "income", "bank account", "account number", "acc no", "credit card",
    "debit card", "card number", "upi", "pan card", "aadhaar", "aadhar",
    "cvv", "net worth", "monthly earning", "savings", "loan amount", "emi",
    "mutual fund", "stock portfolio", "investment", "cryptocurrency", "crypto wallet",
]

EDUCATION_TERMS = [
    "student", "studying", "study", "computer science", "engineering", "b.tech",
    "btech", "b.e", "m.tech", "degree", "university", "college", "school",
    "class 12", "class 10", "semester", "sem ", "graduate", "undergraduate",
    "postgraduate", "enrolled", "internship", "course", "major",
]

ORGANIZATION_TERMS = [
    "indian institute of information technology, pune",
    "indian institute of information technology",
    "indian institute of technology",
    "national institute of technology",
    "iiit pune", "iiit delhi", "iiit hyderabad", "iiit bangalore", "iiit",
    "iit delhi", "iit bombay", "iit madras", "iit kanpur", "iit kharagpur",
    "iit roorkee", "iit guwahati", "iit", "nit trichy", "nit surathkal",
    "nit warangal", "nit", "bits pilani", "iet davv", "davv indore",
    "savitribai phule pune university", "delhi university", "anna university",
    "google", "microsoft", "amazon", "apple", "meta", "tcs", "infosys",
    "wipro", "accenture", "cognizant", "deloitte", "goldman sachs", "nvidia",
]

# ------------------------------------------------------------------ patterns
PATTERNS = [
    # (type, sensitivity, regex, reason, confidence)
    ("email", "HIGH",
     r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
     "Email address detected.", 0.98),
    ("phone", "HIGH",
     r"(?:\+?91[-\s]?)?[6-9]\d{9}\b",
     "Mobile number pattern detected.", 0.95),
    ("phone", "HIGH",
     r"(?:\+?91[-\s]?)?[6-9]\d{4}[-\s]\d{5}\b",
     "Mobile number pattern detected.", 0.92),
    ("phone", "HIGH",
     r"\b\(?[2-9]\d{2}\)?[-\s][2-9]\d{2}[-\s]\d{4}\b",
     "Phone number pattern detected.", 0.88),
    ("credential", "HIGH",
     r"\b(?:mis\s*(?:number|no\.?)|roll\s*(?:number|no\.?)|enrollment\s*(?:number|no\.?)|registration\s*(?:number|no\.?)|reg\s*no\.?|student\s*id|prn|urn)\s*[:=]?\s*([A-Za-z0-9-_/]{4,24})\b",
     "Academic student identifier (Roll / MIS / Registration) detected.", 0.96),
    ("credential", "HIGH",
     r"\b(?:mis|roll|enrollment)\b[\s\S]{1,60}?\b([1-9][0-9]{7,11})\b",
     "Institutional Student ID / MIS identifier detected.", 0.90),
    ("financial", "HIGH",
     r"\b[a-zA-Z0-9.\-_]{2,64}@(?!gmail|yahoo|hotmail|outlook|proton|icloud)[a-zA-Z0-9]{2,32}(?!\.[a-zA-Z]{2,})\b",
     "UPI payment ID detected.", 0.9),
    ("credential", "CRITICAL",
     r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
     "Indian Permanent Account Number (PAN) detected.", 0.96),
    ("credential", "CRITICAL",
     r"(?<!\d)(?:aadhaar|aadhar|uid)?\s*([2-9]\d{3}\s\d{4}\s\d{4})(?!\s*\d)",
     "Aadhaar identification number pattern detected.", 0.92),
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
    ("location", "HIGH",
     r"\b(?:pincode|pin code|pin|zip|zipcode)\s*[:=]?\s*([1-9][0-9]{5})\b",
     "Postal Pincode detected.", 0.95),
    ("contact", "HIGH",
     r"(?:linkedin\.com\/in\/|github\.com\/)([a-zA-Z0-9_-]+)",
     "Social / Professional profile handle detected.", 0.95),
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
    "more", "most", "little", "less", "least", "hello", "hi", "hey",
}

CONTEXT_PATTERNS = [
    # student & person names (documents + conversational)
    ("identity", "Name", "HIGH",
     r"(?:^|\n)\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){1,3})\s*(?:\n|\r|\s*\|\s*|\s*[-–]\s*|\s*,\s*)(?=(?:ai engineer|software engineer|developer|engineer|intern|student|\+?\d{2,}|[a-zA-Z0-9._%+-]+@))",
     "Identity — resume/document header candidate name detected.", 0.96),
    ("identity", "Name", "HIGH",
     r"\b(?:name\s+of\s+student|student\s+name|candidate\s+name|employee\s+name|applicant\s+name)\s*[:=]\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3})",
     "Student / Candidate identity disclosed.", 0.98),
    ("identity", "Name", "HIGH",
     r"\b(?:NAME\s+OF\s+STUDENT|STUDENT\s+NAME|CANDIDATE\s+NAME|FULL\s+NAME|NAME)\s*[:=]\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3})",
     "Identity — person / student name disclosed in document header.", 0.96),
    ("identity", "Name", "HIGH",
     r"\b(?:my name is|i am called|you can call me|call me)\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,2})",
     "Identity — personal name disclosed.", 0.97),
    ("identity", "Name", "HIGH",
     r"\b(?:i'?m|i am)\s+([A-Z][a-z]{2,})\b(?!\s+(?:a|an|the|not|from|in|at|for|to|with|into|about|on|here|there|going|trying|looking|working|studying|waiting|feeling|learning|reading|playing|planning|currently|very|so|just|really|also|now|born|based|living|staying|residing|located)\b)",
     "Identity — first name disclosed.", 0.85),
    # academic metadata
    ("education", "AcademicYear", "LOW",
     r"\b(?:year\s+of\s+admission|admission\s+year|batch)\s*[:=]?\s*(\d{4})\b",
     "Academic admission year detected.", 0.92),
    ("education", "AcademicYear", "LOW",
     r"\b(?:academic\s+year|session)\s*[:=]?\s*(\d{4}(?:\s*-\s*\d{2,4})?)\b",
     "Academic session year detected.", 0.90),
    ("education", "Degree", "LOW",
     r"\b(?:programme|program|degree)\s*[:=]\s*([A-Za-z\s]+?)(?=\s{2,}|\n|\r|$)",
     "Educational programme / degree detected.", 0.90),
    ("education", "Branch", "LOW",
     r"\b(?:branch|department|discipline)\s*[:=]\s*([A-Za-z\s]+?)(?=\s{2,}|\n|\r|$)",
     "Academic branch / specialization detected.", 0.90),
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
    # medical report headers
    ("identity", "Name", "HIGH",
     r"\b(?:patient name|patient|name of patient|pt name)\s*[:=]\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,2})(?=\s{2,}|\s*(?:age|sex|gender|uhid|mrn|dob|\n|\r|$))",
     "Medical report patient name detected.", 0.98),
    ("identity", "Doctor", "HIGH",
     r"\b(?:ref doctor|referred by|referring doctor|doctor|dr\.)\s*[:=]?\s*(?:dr\.?\s*)?([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,2})(?=\s{2,}|\s*(?:md|mbbs|ms|\n|\r|$))",
     "Medical report referring doctor detected.", 0.95),
    ("credential", "PatientID", "CRITICAL",
     r"\b(?:uhid|mrn|barcode|sample id|specimen id|lab no|customer id)\s*[:=]\s*([A-Za-z0-9-_/]{4,32})\b",
     "Medical record identifier (UHID/MRN/Sample ID) detected.", 0.97),
    ("demographic", "Age", "MEDIUM",
     r"\b(?:age\s*[/\\&]\s*gender|age\s*[/\\&]\s*sex|age)\s*[:=]?\s*(\d{1,3})\s*(?:y|years?|yrs?)?\b",
     "Medical report age detected.", 0.92),
    # location / address with sector or area prefix
    ("location", "Location", "HIGH",
     r"\b(?:sector|sec|phase|plot|pocket|block)\s*[-#]?\s*\d+[a-zA-Z]?(?:[\s,]+(?:[A-Z][a-zA-Z]+|\d+))*\b",
     "Exact address / sector coordinate detected.", 0.92),
    ("location", "Location", "MEDIUM",
     r"\b(?:i (?:live|stay|am based|reside)|living|staying|based|located|from|in)\s+(?:in|at)?\s*([A-Za-z0-9\s,-]+?)(?=\s+(?:and|with|for|since|next|\.|\?|!|$))",
     "Location mentioned in context.", 0.85),
    ("location", "Location", "MEDIUM",
     r"\b(?:my (?:city|hometown|home town|native place)|city is|hometown is)\s+is?\s*([A-Za-z0-9\s,-]+?)(?=\s+(?:and|with|\.|\?|!|$))",
     "City / hometown mentioned.", 0.88),
]

HEALTH_RE = re.compile(
    r"\b(" + "|".join(re.escape(t.strip()) for t in HEALTH_TERMS) + r")\b", re.I)
FIN_RE = re.compile(
    r"\b(" + "|".join(re.escape(t.strip()) for t in FINANCIAL_TERMS) + r")\b", re.I)
EDU_RE = re.compile(
    r"\b(" + "|".join(re.escape(t.strip()) for t in EDUCATION_TERMS) + r")\b", re.I)
ORG_RE = re.compile(
    r"\b(" + "|".join(re.escape(t.strip()) for t in ORGANIZATION_TERMS) + r")\b", re.I)


def _dedupe(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    seen = set()
    out = []
    for e in entities:
        key = (e.type, e.value.lower().strip())
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def _city(value: str) -> str | None:
    v = value.strip().lower().rstrip(".,!?")
    if v in CITIES:
        return v
    for c in sorted(CITIES.keys(), key=len, reverse=True):
        if c in v:
            return c
    return None


def detect_all(text: str, source: str = "user_prompt") -> DetectionResult:
    """Main detection entry point — deterministic multi-category detector."""
    t0 = time.perf_counter()
    entities: list[DetectedEntity] = []
    if not text:
        return DetectionResult(source=source, ms=(time.perf_counter() - t0) * 1000)

    lower = text.lower()

    # --- generic patterns (email, phone, crypto, tokens, pan, aadhaar, pincode)
    for typ, sens, rx, reason, conf in PATTERNS:
        for m in re.finditer(rx, text, re.I):
            val = m.group(1).strip(" .,!?\n\r") if (m.groups() and m.group(1)) else m.group(0).strip(" .,!?\n\r")
            if not val:
                continue
            entities.append(DetectedEntity(
                entity=typ.title(), value=val, type=typ, sensitivity=sens,
                reason=reason, confidence=conf,
                context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
            ))

    # --- contextual patterns (names, ages, locations)
    for typ, entity, sens, rx, reason, conf in CONTEXT_PATTERNS:
        for m in re.finditer(rx, text, re.I):
            val = m.group(1).strip(" .,!?") if m.groups() else m.group(0).strip(" .,!?")
            if not val:
                continue
            if typ == "location":
                # Check if it has a known city or address token
                found_city = _city(val) or _city(m.group(0))
                if not found_city and not any(kw in val.lower() for kw in ("sector", "sec ", "phase", "plot", "street", "road", "block", "nagar", "vihar", "enclave")):
                    continue
                # Normalize city name if pure city
                if found_city and len(val.split()) <= 2:
                    val = found_city.title()
            if typ == "identity" and (len(val) < 2 or val.lower() in NAME_STOPWORDS):
                continue
            entities.append(DetectedEntity(
                entity=entity, value=val, type=typ, sensitivity=sens,
                reason=reason, confidence=conf,
                context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
            ))

    # --- direct city scan across text
    for city_name, reg in sorted(CITIES.items(), key=lambda x: len(x[0]), reverse=True):
        pattern = r"\b" + re.escape(city_name) + r"\b"
        for m in re.finditer(pattern, lower):
            # Check if already covered by an address entity
            entities.append(DetectedEntity(
                entity="Location", value=city_name.title(), type="location", sensitivity="MEDIUM",
                reason=f"Direct city reference '{city_name.title()}' detected ({reg}).", confidence=0.95,
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

    # --- health / financial / education / organization lexicons
    for m in HEALTH_RE.finditer(lower):
        entities.append(DetectedEntity(
            entity="Health", value=m.group(1).strip(), type="health", sensitivity="CRITICAL",
            reason="Health/Medical information disclosed.", confidence=0.88,
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
    for m in ORG_RE.finditer(lower):
        entities.append(DetectedEntity(
            entity="Organization", value=m.group(1).strip().upper() if len(m.group(1)) <= 5 else m.group(1).title(),
            type="organization", sensitivity="MEDIUM",
            reason="Organization or Institution identifier disclosed.", confidence=0.85,
            context=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " "),
        ))

    return DetectionResult(
        source=source,
        entities=_dedupe(entities),
        ms=(time.perf_counter() - t0) * 1000,
    )
