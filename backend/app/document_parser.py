"""Document and PDF parsing engine for MEMVERSE.

Extracts text from uploaded PDF files, plain text, and markdown files.
Provides built-in sample diagnostic reports for instant demonstration.
"""
import io
import re
from typing import BinaryIO

SAMPLE_REPORTS = {
    "blood_sugar_lipid": {
        "title": "Comprehensive Diabetic & Lipid Profile",
        "filename": "MaxCare_Lab_Report_Satvik.pdf",
        "text": """MAXCARE DIAGNOSTIC PATHLAB & RESEARCH CENTER
Address: Plot 42, Sector 62, Noida, Uttar Pradesh 201309 | Ph: +91 9811223344
================================================================================
PATIENT DETAILS
Patient Name: Satvik Kesarwani          Age / Gender: 24 Y / Male
UHID / MRN: MC-2026-98741              Ref Doctor: Dr. Arvind Sharma, MD (Med)
Collection Date: 02-Sep-2026 08:30 AM  Sample ID: SMP-882194
Registered Phone: +91 9876543210       Email: satvik.kesarwani@gmail.com
================================================================================
BIOCHEMISTRY & METABOLIC PANEL

TEST NAME                      RESULT       UNITS      REFERENCE INTERVAL
--------------------------------------------------------------------------------
Fasting Blood Sugar (Glucose)  142.0  [HIGH] mg/dL      70.0 - 99.0
HbA1c (Glycated Hemoglobin)     7.4   [HIGH] %          < 5.7 (Normal), 5.7-6.4 (Prediabetic), >= 6.5 (Diabetic)
Estimated Avg Glucose (eAG)    165.5  [HIGH] mg/dL      90.0 - 120.0

LIPID PROFILE
Total Cholesterol              238.0  [HIGH] mg/dL      < 200.0 (Desirable)
Triglycerides                  210.0  [HIGH] mg/dL      < 150.0 (Normal)
HDL Cholesterol (Good)          38.0  [LOW]  mg/dL      > 40.0 (Normal)
LDL Cholesterol (Calculated)   158.0  [HIGH] mg/dL      < 100.0 (Optimal)
VLDL Cholesterol                42.0  [HIGH] mg/dL      < 30.0

RENAL FUNCTION
Serum Creatinine                 0.95        mg/dL      0.70 - 1.30
Blood Urea Nitrogen (BUN)       14.2         mg/dL      7.0 - 20.0
================================================================================
CLINICAL INTERPRETATION:
- Elevated Fasting Plasma Glucose and HbA1c indicative of poorly controlled Type 2 Diabetes Mellitus.
- Mixed Dyslipidemia with hypertriglyceridemia and elevated LDL cholesterol.
- Renal parameters are within normal limits.
Advice: Immediate endocrinologist/physician consultation for anti-diabetic and lipid-lowering pharmacotherapy.
--------------------------------------------------------------------------------
*** End of Lab Report - Verified by Dr. R. K. Gupta, MD (Pathology) ***
"""
    },
    "complete_blood_count": {
        "title": "Complete Blood Count (CBC) & Infection Panel",
        "filename": "Apollo_Diagnostics_CBC_Report.pdf",
        "text": """APOLLO DIAGNOSTICS - CLINICAL HEMATOLOGY
Center: Indira Nagar, Lucknow, Uttar Pradesh | Ph: +91 9415012345
================================================================================
PATIENT DEMOGRAPHICS
Name: Priya Sharma                      Age: 29 Years    Gender: Female
UHID: APL-LK-554129                     Referred By: Dr. Meenakshi Roy
Barcode: BAR-9988112                    Collected: 01-Sep-2026 10:15 AM
Address: Flat 402, Royal Palms, Sector 18, Lucknow | Contact: +91 9123456780
================================================================================
COMPLETE BLOOD COUNT (CBC)

PARAMETER                      OBSERVED     UNITS      BIOLOGICAL REF INTERVAL
--------------------------------------------------------------------------------
Hemoglobin (Hb)                  9.4  [LOW]  g/dL       12.0 - 15.5
Total RBC Count                  3.6  [LOW]  mil/uL     4.0 - 5.2
PCV (Packed Cell Volume)        30.2  [LOW]  %          36.0 - 46.0
MCV                             72.1  [LOW]  fL         80.0 - 100.0
MCH                             24.2  [LOW]  pg         27.0 - 32.0
MCHC                            31.0  [LOW]  g/dL       32.0 - 36.0

Total Leucocyte Count (WBC)    12,400 [HIGH] /uL        4,000 - 11,000
- Neutrophils                     78  [HIGH] %          40 - 70
- Lymphocytes                     16  [LOW]  %          20 - 40
- Monocytes                        4         %          2 - 8
- Eosinophils                      2         %          1 - 6

Platelet Count                 1,35,000 [LOW] /uL       1,50,000 - 4,50,000
================================================================================
MICROSCOPIC EXAMINATION:
- RBC Morphology: Microcytic, Hypochromic with mild anisopoikilocytosis.
- WBC: Neutrophilic leukocytosis with toxic granules noted.
- Platelets: Reduced on smear.
Impression: Microcytic hypochromic anemia (suggestive of Iron Deficiency) with mild acute reactive leukocytosis and mild thrombocytopenia.
--------------------------------------------------------------------------------
Dr. S. K. Verma, MD (Path) | Chief Hematologist
"""
    },
    "liver_function": {
        "title": "Liver Function Test (LFT Panel)",
        "filename": "Thyrocare_LFT_Report.pdf",
        "text": """THYROCARE LABORATORIES LIMITED
Navi Mumbai, Maharashtra 400703 | Email: reports@thyrocare.com
================================================================================
PATIENT INFORMATION
Patient: Rajesh Verma                  Age / Sex: 45 Y / Male
Customer ID: THY-662914                Ref By: Dr. N. K. Bansal
Phone: +91 9820011223                  Aadhaar: 5544 3322 1100
================================================================================
LIVER FUNCTION TEST (LFT)

INVESTIGATION                  VALUE        UNITS      NORMAL RANGE
--------------------------------------------------------------------------------
Bilirubin - Total                2.4  [HIGH] mg/dL      0.2 - 1.2
Bilirubin - Direct               1.1  [HIGH] mg/dL      0.0 - 0.3
Bilirubin - Indirect             1.3  [HIGH] mg/dL      0.1 - 0.9

SGOT / AST                      98.0  [HIGH] U/L        10.0 - 40.0
SGPT / ALT                     135.0  [HIGH] U/L        10.0 - 45.0
Alkaline Phosphatase (ALP)     180.0  [HIGH] U/L        40.0 - 140.0
Gamma GT (GGTP)                 85.0  [HIGH] U/L        10.0 - 50.0

Total Protein                    7.1         g/dL       6.4 - 8.3
Albumin                          4.0         g/dL       3.5 - 5.0
Globulin                         3.1         g/dL       2.0 - 3.5
A/G Ratio                        1.29                   1.0 - 2.0
================================================================================
IMPRESSION:
- Acute hepatocellular injury pattern with elevated transaminases (ALT > AST) and conjugated hyperbilirubinemia.
- Correlate clinically with viral markers, ultrasound abdomen, and medication history.
"""
    }
}


def extract_text_from_pdf(file_bytes: bytes, filename: str = "document.pdf") -> dict:
    """Extract clean text and metadata from uploaded PDF bytes."""
    extracted_text = []
    page_count = 0
    metadata = {}

    # 1. Try PyPDF
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(file_bytes))
        page_count = len(reader.pages)
        if reader.metadata:
            metadata = {k.strip("/"): str(v) for k, v in reader.metadata.items() if v}
        for idx, page in enumerate(reader.pages):
            txt = page.extract_text() or ""
            if txt.strip():
                extracted_text.append(f"--- PAGE {idx + 1} ---\n{txt}")
    except Exception as e_pypdf:
        # 2. Fallback to pdfplumber
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                page_count = len(pdf.pages)
                metadata = pdf.metadata or {}
                for idx, page in enumerate(pdf.pages):
                    txt = page.extract_text() or ""
                    if txt.strip():
                        extracted_text.append(f"--- PAGE {idx + 1} ---\n{txt}")
        except Exception as e_pdfplumber:
            return {
                "success": False,
                "error": f"Failed to extract PDF text: {str(e_pypdf)} / {str(e_pdfplumber)}",
                "filename": filename,
                "text": "",
                "pages": 0,
            }

    full_text = "\n\n".join(extracted_text).strip()
    if not full_text:
        return {
            "success": False,
            "error": "The uploaded PDF appears to be empty or contains scanned non-OCR images.",
            "filename": filename,
            "text": "",
            "pages": page_count,
        }

    return {
        "success": True,
        "filename": filename,
        "text": full_text,
        "pages": page_count,
        "char_count": len(full_text),
        "metadata": metadata,
    }


def parse_document_file(file_bytes: bytes, filename: str) -> dict:
    """Parse PDF, plain text, or markdown file."""
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    if ext == "pdf":
        return extract_text_from_pdf(file_bytes, filename)
    elif ext in ("txt", "md", "csv", "json"):
        try:
            text = file_bytes.decode("utf-8", errors="replace").strip()
            return {
                "success": True,
                "filename": filename,
                "text": text,
                "pages": 1,
                "char_count": len(text),
                "metadata": {},
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to read text file: {str(e)}", "filename": filename, "text": "", "pages": 0}
    else:
        return {
            "success": False,
            "error": f"Unsupported file type '.{ext}'. Please upload a PDF (.pdf) or text document (.txt, .md).",
            "filename": filename,
            "text": "",
            "pages": 0,
        }
