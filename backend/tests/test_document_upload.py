"""Tests for document upload and medical report PII sanitization."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import db
from gateway import MemverseGateway
import document_parser
import detector


def _gw(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "doc_test.db"))
    return MemverseGateway()


def test_sample_reports_available():
    assert "blood_sugar_lipid" in document_parser.SAMPLE_REPORTS
    assert "complete_blood_count" in document_parser.SAMPLE_REPORTS
    assert "liver_function" in document_parser.SAMPLE_REPORTS
    for k, v in document_parser.SAMPLE_REPORTS.items():
        assert len(v["text"]) > 100
        assert v["filename"].endswith(".pdf")


def test_medical_report_pii_detection():
    sample = document_parser.SAMPLE_REPORTS["blood_sugar_lipid"]["text"]
    det = detector.detect_all(sample)
    
    entities = {e.value for e in det.entities}
    # Assert sensitive patient identifiers were detected
    assert any("Satvik Kesarwani" in e for e in entities)
    assert any("MC-2026-98741" in e for e in entities)
    assert any("satvik.kesarwani@gmail.com" in e for e in entities)
    assert any("9876543210" in e for e in entities)


def test_medical_report_zero_trust_redaction(tmp_path, monkeypatch):
    gw = _gw(tmp_path, monkeypatch)
    sample = document_parser.SAMPLE_REPORTS["blood_sugar_lipid"]
    
    full_prompt = (
        f"Please explain this medical report in plain language.\n\n"
        f"--- ATTACHED REPORT ({sample['filename']}) ---\n"
        f"{sample['text']}"
    )
    
    r = gw.process_chat(full_prompt, purpose="medical_report_analysis", destination="nvidia")
    
    assert r.blocked is False
    assert r.trace.summary["decision"] in ("TRANSFORM", "ALLOW")
    assert r.trace.summary["egress"] == "CLEAN"
    
    # Verify patient personal identifiers did NOT leak into the model payload
    all_msg_content = " ".join(m["content"] for m in r.model_input.get("messages", []))
    assert "Satvik Kesarwani" not in all_msg_content
    assert "satvik.kesarwani@gmail.com" not in all_msg_content
    assert "MC-2026-98741" not in all_msg_content
    assert "+91 9876543210" not in all_msg_content
    
    # Verify clinical diagnostic metrics were preserved for the AI to explain
    assert "142.0" in all_msg_content  # Glucose reading
    assert "7.4" in all_msg_content    # HbA1c reading
    assert "238.0" in all_msg_content  # Cholesterol reading
