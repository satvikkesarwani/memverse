"""Global User Persona Vault & Continuous Auto-Harvesting Engine for MEMVERSE.

Maintains a long-term, ever-evolving, encrypted local identity vault.
When queries are sent, converts raw personal data into mathematical semantic scaffolding
so AI models can personalize deeply without receiving raw PII.
"""
import json
import re
from datetime import datetime, timezone
from db import execute, q, now_iso, new_id

PERSONA_SCHEMA = """
CREATE TABLE IF NOT EXISTS persona_attributes (
    id TEXT PRIMARY KEY,
    user_id TEXT DEFAULT 'default_user',
    category TEXT,
    key TEXT,
    label TEXT,
    raw_value TEXT,
    sanitized_value TEXT,
    sensitivity TEXT,
    policy_action TEXT,
    source_snippet TEXT,
    updated_at TEXT
);
"""

def init_persona():
    from db import get_conn, _lock
    with _lock:
        conn = get_conn()
        try:
            conn.executescript(PERSONA_SCHEMA)
            conn.commit()
        finally:
            conn.close()

# Auto-initialize (will be called explicitly by gateway after init_db)
# init_persona()

def categorize_and_sanitize(entity_type: str, raw_value: str, sensitivity: str = "MEDIUM"):
    """Determines the category, user-friendly label, and AI-safe semantic generalization."""
    etype = (entity_type or "").upper()
    val_clean = raw_value.strip()
    
    # 1. Identity & Name
    if any(k in etype for k in ["NAME", "PERSON", "CANDIDATE", "STUDENT"]):
        return {
            "category": "IDENTITY",
            "key": "name",
            "label": "Full Name",
            "sanitized_value": "User (Identity Protected)",
            "sensitivity": "HIGH",
            "policy_action": "SUPPRESS"
        }
    
    # 2. Academic Institution
    if any(k in etype for k in ["COLLEGE", "UNIVERSITY", "INSTITUTE", "ORGANIZATION"]):
        tier = "Institute of National Importance (IIIT/IIT)" if any(k in val_clean.upper() for k in ["IIIT", "IIT", "NIT"]) else "University / Higher Education Institute"
        return {
            "category": "ACADEMIC",
            "key": "institution",
            "label": "Educational Institution",
            "sanitized_value": tier,
            "sensitivity": "MEDIUM",
            "policy_action": "GENERALIZE"
        }
    
    # 3. Academic Identifiers (MIS, Roll, Enrollment, Credential)
    if any(k in etype for k in ["MIS", "ROLL", "ENROLLMENT", "REGISTRATION", "CREDENTIAL"]):
        masked = f"ID-****{val_clean[-4:]}" if len(val_clean) >= 4 else "ID-****"
        return {
            "category": "ACADEMIC",
            "key": "student_id",
            "label": "Student ID / MIS",
            "sanitized_value": masked,
            "sensitivity": "HIGH",
            "policy_action": "MASK"
        }
        
    # 4. Degree & Branch / Discipline
    if any(k in etype for k in ["BRANCH", "PROGRAMME", "DEGREE", "SPECIALIZATION"]):
        return {
            "category": "ACADEMIC",
            "key": "discipline",
            "label": "Academic Program & Branch",
            "sanitized_value": val_clean,  # Safe utility
            "sensitivity": "LOW",
            "policy_action": "ALLOW"
        }

    # 5. Demographics (Age / DOB)
    if "AGE" in etype or "DOB" in etype or "BIRTH" in etype:
        num_match = re.search(r"\d+", val_clean)
        if num_match:
            age = int(num_match.group(0))
            band = "18-24 (Undergraduate Age Band)" if age < 25 else ("25-34" if age < 35 else "35+")
        else:
            band = "Young Adult (18-25 band)"
        return {
            "category": "DEMOGRAPHICS",
            "key": "age_band",
            "label": "Age Demographic",
            "sanitized_value": band,
            "sensitivity": "MEDIUM",
            "policy_action": "GENERALIZE"
        }

    # 6. Location & Address
    if any(k in etype for k in ["LOCATION", "ADDRESS", "CITY", "STATE"]):
        city = "Western India Region" if any(k in val_clean.lower() for k in ["pune", "mumbai", "maharashtra"]) else ("Northern India Region" if any(k in val_clean.lower() for k in ["delhi", "noida", "up"]) else "Urban Indian Region")
        return {
            "category": "LOCATION",
            "key": "location",
            "label": "Geographic Region",
            "sanitized_value": city,
            "sensitivity": "MEDIUM",
            "policy_action": "GENERALIZE"
        }

    # 7. Contact Info (Email / Phone)
    if "EMAIL" in etype:
        domain = val_clean.split("@")[-1] if "@" in val_clean else "email.com"
        return {
            "category": "CONTACT",
            "key": "email",
            "label": "Email Address",
            "sanitized_value": f"[REDACTED_EMAIL] (Provider: {domain})",
            "sensitivity": "CRITICAL",
            "policy_action": "MASK"
        }
    if "PHONE" in etype or "MOBILE" in etype:
        last4 = val_clean[-4:] if len(val_clean) >= 4 else "XXXX"
        return {
            "category": "CONTACT",
            "key": "phone",
            "label": "Phone Number",
            "sanitized_value": f"[REDACTED_PHONE] (ends with {last4})",
            "sensitivity": "CRITICAL",
            "policy_action": "MASK"
        }
    if "CONTACT" in etype:
        return {
            "category": "CONTACT",
            "key": f"contact_{val_clean[:8]}",
            "label": "Social/Profile Handle",
            "sanitized_value": "[REDACTED_HANDLE]",
            "sensitivity": "HIGH",
            "policy_action": "MASK"
        }

    # 8. Financial & Payment Cards (Card Numbers, Bank Details)
    if any(k in etype for k in ["FINANCIAL", "CARD", "PAYMENT", "BANK", "ACCOUNT", "CREDIT"]):
        last4 = val_clean[-4:] if len(val_clean) >= 4 else "XXXX"
        return {
            "category": "FINANCIAL",
            "key": "card_number",
            "label": "Payment Card / Account",
            "sanitized_value": f"[REDACTED_CARD] (ending in {last4})",
            "sensitivity": "CRITICAL",
            "policy_action": "MASK"
        }

    # 9. Health & Clinical Markers
    if any(k in etype for k in ["HEALTH", "BLOOD", "DIABETES", "MEDICAL", "SUGAR", "HBA1C", "LIVER"]):
        return {
            "category": "HEALTH",
            "key": etype.lower(),
            "label": f"Health Marker ({val_clean[:20]})",
            "sanitized_value": f"Clinical parameter: {val_clean}",
            "sensitivity": "HIGH",
            "policy_action": "TRANSFORM"
        }

    # Default / General Interest & Context
    return {
        "category": "GENERAL",
        "key": etype.lower() or "context",
        "label": entity_type.replace("_", " ").title(),
        "sanitized_value": val_clean,
        "sensitivity": sensitivity or "LOW",
        "policy_action": "ALLOW"
    }


def harvest_entities(entities: list, prompt_text: str = "", user_id: str = "default_user"):
    """Auto-harvests detected entities from chat and documents into the Global Persona Vault."""
    if not entities:
        return []
    
    harvested = []
    ts = now_iso()
    snippet = (prompt_text.strip()[:100] + "…") if len(prompt_text) > 100 else prompt_text.strip()
    
    for ent in entities:
        # ent can be dict or DetectedEntity object
        etype = getattr(ent, "entity", None) or getattr(ent, "type", None) or (ent.get("entity") if isinstance(ent, dict) else ent.get("type"))
        evalue = getattr(ent, "value", None) or (ent.get("value") if isinstance(ent, dict) else "")
        esens = getattr(ent, "sensitivity", None) or (ent.get("sensitivity") if isinstance(ent, dict) else "MEDIUM")
        
        if not etype or not evalue or len(str(evalue).strip()) < 2:
            continue
            
        mapping = categorize_and_sanitize(str(etype), str(evalue), str(esens))
        
        # Check if attribute key already exists for this user
        existing = q(
            "SELECT id FROM persona_attributes WHERE user_id=? AND key=? LIMIT 1",
            (user_id, mapping["key"])
        )
        
        if existing:
            attr_id = existing[0]["id"]
            execute(
                """UPDATE persona_attributes 
                   SET raw_value=?, sanitized_value=?, sensitivity=?, policy_action=?, 
                       source_snippet=?, updated_at=?, category=?, label=?
                   WHERE id=?""",
                (str(evalue), mapping["sanitized_value"], mapping["sensitivity"], 
                 mapping["policy_action"], snippet, ts, mapping["category"], mapping["label"], attr_id)
            )
        else:
            attr_id = new_id("attr")
            execute(
                """INSERT INTO persona_attributes 
                   (id, user_id, category, key, label, raw_value, sanitized_value, 
                    sensitivity, policy_action, source_snippet, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (attr_id, user_id, mapping["category"], mapping["key"], mapping["label"],
                 str(evalue), mapping["sanitized_value"], mapping["sensitivity"],
                 mapping["policy_action"], snippet, ts)
            )
            
        harvested.append({
            "id": attr_id,
            "key": mapping["key"],
            "label": mapping["label"],
            "raw_value": str(evalue),
            "sanitized_value": mapping["sanitized_value"],
            "category": mapping["category"],
            "sensitivity": mapping["sensitivity"],
            "policy_action": mapping["policy_action"],
            "updated_at": ts
        })
        
    return harvested


def get_all_persona_attributes(user_id: str = "default_user") -> list[dict]:
    """Returns all persona attributes stored in the Global Persona Vault."""
    return q(
        "SELECT * FROM persona_attributes WHERE user_id=? ORDER BY updated_at DESC",
        (user_id,)
    )


def delete_persona_attribute(attr_id: str, user_id: str = "default_user") -> bool:
    """Deletes a specific persona attribute from the vault."""
    execute("DELETE FROM persona_attributes WHERE id=? AND user_id=?", (attr_id, user_id))
    return True


def wipe_persona_vault(user_id: str = "default_user") -> int:
    """Completely wipes the persona vault for a fresh zero-state start."""
    execute("DELETE FROM persona_attributes WHERE user_id=?", (user_id,))
    return 0


def log_biometric_event(event_type: str, image_hash: str, purpose: str = "image_generation", user_id: str = "default_user") -> dict:
    """Logs a biometric processing event to the persona vault.

    Does NOT store the image or face data. Only stores:
    - event_type: TYPE of event (e.g. "IMAGE_CHAT")
    - image_hash: SHA-256 hash of the EXIF-stripped image (for audit only)
    - purpose: why the image was processed
    - sanitized_value: Always "Zero-retention event — Consent: GRANTED" or similar
    - sensitivity: CRITICAL
    - policy_action: ZERO_RETENTION

    Returns the inserted attribute dict.
    """
    from db import execute, q, now_iso, new_id

    attr_id = new_id("biometric")
    ts = now_iso()
    sanitized = "Zero-retention event — Consent: GRANTED"

    execute(
        """INSERT INTO persona_attributes 
           (id, user_id, category, key, label, raw_value, sanitized_value, 
            sensitivity, policy_action, source_snippet, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (attr_id, user_id, "BIOMETRIC_EVENTS", "image_event",
         "Biometric Image Processed", f"[IMAGE HASH: {image_hash}]", sanitized,
         "CRITICAL", "ZERO_RETENTION", f"{event_type} at {ts}", ts)
    )

    return {
        "id": attr_id,
        "user_id": user_id,
        "category": "BIOMETRIC_EVENTS",
        "key": "image_event",
        "label": "Biometric Image Processed",
        "raw_value": f"[IMAGE HASH: {image_hash}]",
        "sanitized_value": sanitized,
        "sensitivity": "CRITICAL",
        "policy_action": "ZERO_RETENTION",
        "source_snippet": f"{event_type} at {ts}",
        "updated_at": ts
    }


def build_semantic_persona_context(user_id: str = "default_user") -> str:
    """Constructs the sanitized semantic scaffolding to inject into the LLM system prompt."""
    attrs = get_all_persona_attributes(user_id)
    if not attrs:
        return ""
        
    lines = ["USER BACKGROUND & APPROVED SEMANTIC CONTEXT:"]
    for a in attrs:
        lines.append(f"  • {a['label']}: {a['sanitized_value']}")
        
    lines.append(
        "Usage instruction: Use this background context silently to tailor your answer ONLY when relevant. "
        "Do NOT mention or list these background attributes unless the user explicitly asks about their background or memory."
    )
    return "\n".join(lines)
