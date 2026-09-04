import os
import sys
from playwright.sync_api import sync_playwright

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

FORMAL_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

@page {
  size: A4;
  margin: 20mm 20mm 20mm 20mm;
  @bottom-right {
    content: "Page " counter(page) " of " counter(pages);
    font-family: 'Inter', sans-serif;
    font-size: 8pt;
    color: #6b7280;
  }
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  color: #111827;
  background: #ffffff;
  line-height: 1.6;
  font-size: 9.5pt;
}

.doc-header {
  border-bottom: 1.5px solid #111827;
  padding-bottom: 12px;
  margin-bottom: 20px;
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
}

.institution-tag {
  font-size: 8.5pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #111827;
}

.doc-meta {
  text-align: right;
  font-size: 8.5pt;
  color: #4b5563;
}

h1 {
  font-size: 16pt;
  font-weight: 700;
  color: #111827;
  letter-spacing: -0.3px;
  line-height: 1.3;
  margin-bottom: 6px;
}

.doc-subtitle {
  font-size: 10pt;
  color: #4b5563;
  margin-bottom: 18px;
}

h2 {
  font-size: 11.5pt;
  font-weight: 700;
  color: #111827;
  margin-top: 18px;
  margin-bottom: 8px;
  padding-bottom: 4px;
  border-bottom: 1px solid #e5e7eb;
}

h3 {
  font-size: 10pt;
  font-weight: 600;
  color: #1f2937;
  margin-top: 12px;
  margin-bottom: 4px;
}

p {
  margin-bottom: 10px;
  color: #374151;
  text-align: justify;
}

ul, ol {
  margin-left: 20px;
  margin-bottom: 12px;
  color: #374151;
}

li {
  margin-bottom: 4px;
}

.formal-section {
  margin: 14px 0;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0;
  font-size: 8.5pt;
}

th {
  border-top: 1.5px solid #111827;
  border-bottom: 1.5px solid #111827;
  color: #111827;
  font-weight: 600;
  text-align: left;
  padding: 8px 6px;
}

td {
  padding: 8px 6px;
  border-bottom: 1px solid #e5e7eb;
  color: #374151;
  vertical-align: top;
}

tr:last-child td {
  border-bottom: 1.5px solid #111827;
}

.link-text {
  font-family: 'JetBrains Mono', monospace;
  color: #1d4ed8;
  text-decoration: none;
  font-size: 8.5pt;
  word-break: break-all;
}

.link-item {
  margin-bottom: 12px;
}

.link-label {
  font-weight: 600;
  color: #111827;
  margin-bottom: 2px;
}

.link-desc {
  font-size: 8.5pt;
  color: #4b5563;
  margin-bottom: 3px;
}

.code-inline {
  font-family: 'JetBrains Mono', monospace;
  font-size: 8pt;
  color: #111827;
  background: #f3f4f6;
  padding: 1px 4px;
  border-radius: 2px;
}

.page-break {
  page-break-after: always;
}

.footer-line {
  margin-top: 30px;
  padding-top: 8px;
  border-top: 1px solid #e5e7eb;
  display: flex;
  justify-content: space-between;
  font-size: 8pt;
  color: #6b7280;
}
"""

HTML_ONE_PAGE = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>MEMVERSE - Project Submission Summary</title>
  <style>
    {FORMAL_CSS}
    @page {{
      size: A4;
      margin: 14mm 18mm 14mm 18mm;
      @bottom-right {{ content: none; }}
    }}
    body {{
      font-size: 9pt;
      line-height: 1.45;
    }}
    h1 {{ font-size: 15pt; margin-bottom: 4px; }}
    .doc-subtitle {{ font-size: 9pt; margin-bottom: 12px; }}
    h2 {{ font-size: 11pt; margin-top: 12px; margin-bottom: 6px; padding-bottom: 2px; }}
    p {{ margin-bottom: 6px; }}
    table {{ margin: 6px 0; font-size: 8.5pt; }}
    th, td {{ padding: 5px 6px; }}
    .link-item {{ margin-bottom: 8px; }}
    .link-label {{ font-size: 8.5pt; }}
    .link-desc {{ font-size: 8pt; margin-bottom: 2px; }}
    .link-text {{ font-size: 8pt; }}
    .doc-header {{ margin-bottom: 12px; padding-bottom: 8px; }}
    .footer-line {{ margin-top: 14px; padding-top: 6px; }}
  </style>
</head>
<body>

  <div class="doc-header">
    <div>
      <div class="institution-tag">PROJECT SUBMISSION SHEET</div>
      <div style="font-size: 12pt; font-weight: 700; color: #111827; margin-top: 2px;">MEMVERSE</div>
    </div>
    <div class="doc-meta">
      Academic Year: 2025–2026<br>
      Date: September 4, 2026
    </div>
  </div>

  <h1>MEMVERSE: Zero-Trust Privacy Gateway for Multimodal AI Memory</h1>
  <div class="doc-subtitle">A client-governed security architecture reconciling personalization and data privacy in large language models.</div>

  <h2>1. Project Description</h2>
  <p>
    MEMVERSE is a zero-trust privacy gateway designed to enable continuous, personalized AI interactions without exposing raw personal identifiers to external model providers. By enforcing a 12-stage security pipeline with dynamic policy transformations, cryptographic memory passports, and tamper-evident audit ledgers, MEMVERSE ensures that external LLMs receive only the minimum necessary generalized semantic context required to answer user queries across text, structured documents, and facial biometrics.
  </p>

  <h2>2. Team Details</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 25%;">Role</th>
        <th style="width: 30%;">Name</th>
        <th style="width: 45%;">Affiliation & Identification</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Project Lead & Developer</strong></td>
        <td>Satvik Kesarwani</td>
        <td>
          Indian Institute of Information Technology (IIIT), Pune<br>
          B.Tech, Computer Science and Engineering<br>
          MIS Number: 112315166
        </td>
      </tr>
      <tr>
        <td><strong>Team Identifier</strong></td>
        <td colspan="2">Team MEMVERSE</td>
      </tr>
    </tbody>
  </table>

  <h2>3. Project Deliverables & Submission Links</h2>
  
  <div class="link-item">
    <div class="link-label">1. Live Working Prototype (Frontend Application)</div>
    <div class="link-desc">Interactive web client featuring real-time chat, policy exploration, memory passport management, and 12-stage trace inspection:</div>
    <a class="link-text" href="https://memverse-satvikkesarwanis-projects.vercel.app">https://memverse-satvikkesarwanis-projects.vercel.app</a>
  </div>

  <div class="link-item">
    <div class="link-label">2. Gateway API Service (Backend)</div>
    <div class="link-desc">FastAPI zero-trust gateway service integrated with live NVIDIA NIM models and cryptographic ledger endpoints:</div>
    <a class="link-text" href="https://memverse-api.onrender.com/api/status">https://memverse-api.onrender.com/api/status</a>
  </div>

  <div class="link-item">
    <div class="link-label">3. Source Code Repository</div>
    <div class="link-desc">Complete project source code repository including backend services, frontend application, and test suites:</div>
    <a class="link-text" href="https://github.com/satvikkesarwani/memverse">https://github.com/satvikkesarwani/memverse</a>
  </div>

  <div class="link-item">
    <div class="link-label">4. Project Details & Demonstration Media</div>
    <div class="link-desc">Submission repository containing project demonstration recordings, architecture diagrams, and supporting documentation:</div>
    <a class="link-text" href="https://drive.google.com/drive/folders/1UO3jMmCsiOP9CiwQckT6S5NyeJYVo_f9?usp=sharing">https://drive.google.com/drive/folders/1UO3jMmCsiOP9CiwQckT6S5NyeJYVo_f9?usp=sharing</a>
  </div>

  <div class="footer-line">
    <span>MEMVERSE Official Project Submission</span>
    <span>Author: Satvik Kesarwani (IIIT Pune)</span>
  </div>

</body>
</html>
"""

HTML_DOC1 = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>MEMVERSE - Problem Definition and Rationale</title>
  <style>{FORMAL_CSS}</style>
</head>
<body>

  <div class="doc-header">
    <div>
      <div class="institution-tag">TECHNICAL REPORT & PROBLEM SPECIFICATION</div>
      <div style="font-size: 13pt; font-weight: 700; color: #111827; margin-top: 2px;">MEMVERSE</div>
    </div>
    <div class="doc-meta">
      Document ID: TR-2026-01<br>
      Date: September 4, 2026
    </div>
  </div>

  <h1>The Privacy-Personalization Dilemma in Large Language Models</h1>
  <div class="doc-subtitle">Analysis of Contextual Over-Disclosure and the Need for Zero-Trust Memory Gateways</div>

  <h2>1. Executive Summary & Problem Definition</h2>
  <p>
    As Large Language Models (LLMs) are deployed as persistent digital assistants, system architectures increasingly incorporate long-term memory to maintain context across sessions. However, current implementations suffer from a critical security flaw: <strong>contextual over-disclosure</strong>.
  </p>
  <p>
    In conventional memory architectures, whenever a user query requires contextual information, the system retrieves raw, unredacted records from storage (such as user names, government identifiers, precise academic marks, salary figures, and medical conditions) and appends them directly into the model's prompt payload.
  </p>
  <p>
    In the vast majority of user tasks, an LLM does not require raw Personally Identifiable Information (PII) to synthesize an accurate and helpful response. For example, to offer career guidance based on an academic transcript, the model requires knowledge of academic standing and completed coursework disciplines—not the student's registration number, date of birth, or exact GPA decimals. Transmitting raw PII exposes users to permanent cloud log retention, training data contamination, and adversarial exfiltration.
  </p>

  <h2>2. The Personalization vs. Privacy Tradeoff</h2>
  <p>
    Users and organizations are currently confronted with two suboptimal extremes:
  </p>
  <ul>
    <li><strong>Full Personalization with Zero Privacy:</strong> Private data is persistently stored in cleartext and transmitted to third-party model hosts without boundary enforcement.</li>
    <li><strong>Full Privacy with Zero Personalization:</strong> Sessions are strictly ephemeral, requiring users to manually re-enter context in every prompt and sacrificing conversational continuity.</li>
  </ul>
  <p>
    MEMVERSE eliminates this tradeoff by introducing <em>Contextual Least Privilege</em>—ensuring the model receives sufficient semantic abstractions to maintain personalization while mathematically withholding sensitive raw identifiers.
  </p>

  <h2>3. Quantitative Comparison: Raw Transmission vs. Contextual Necessity</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 25%;">Domain</th>
        <th style="width: 35%;">Current LLM Payload (Raw PII)</th>
        <th style="width: 40%;">Minimal Context Required for Synthesis</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Student Record</strong></td>
        <td><code>"Satvik Kesarwani, MIS: 112315166, IIIT Pune"</code></td>
        <td><code>"Undergraduate, Technical Institute, Western India"</code></td>
      </tr>
      <tr>
        <td><strong>Academic Metrics</strong></td>
        <td><code>"Semester VI SGPA: 9.00, Cumulative CGPA: 8.57"</code></td>
        <td><code>"Top Quartile Academic Standing"</code></td>
      </tr>
      <tr>
        <td><strong>Financial History</strong></td>
        <td><code>"Monthly Account Balance: INR 1,45,200 at HDFC"</code></td>
        <td><code>"Moderate Liquidity Tier"</code></td>
      </tr>
      <tr>
        <td><strong>Employment & Compensation</strong></td>
        <td><code>"Senior Engineer at Microsoft, Base: $165,000"</code></td>
        <td><code>"Tier-1 Technology Enterprise Experience"</code></td>
      </tr>
      <tr>
        <td><strong>Health Data</strong></td>
        <td><code>"Diagnosed with Chronic Hypertension on 2023"</code></td>
        <td><code>"Cardiovascular Management Consideration"</code></td>
      </tr>
    </tbody>
  </table>

  <div class="page-break"></div>

  <h2>4. Threat Vectors in Unbounded LLM Memory</h2>
  
  <h3>4.1 Adversarial Prompt Injection and Memory Exfiltration</h3>
  <p>
    Without an intermediary gateway, attackers can utilize indirect prompt injections (e.g., instructions embedded in retrieved documents or conversational jailbreaks) to command the model to output its complete system context, thereby leaking all accumulated memory.
  </p>

  <h3>4.2 Third-Party Egress and Regulatory Violations</h3>
  <p>
    Transmitting unredacted PII across external API boundaries violates regulatory frameworks including GDPR (Article 5 Data Minimization, Article 17 Right to Erasure) and DPDP regulations. When personal identifiers enter third-party logging pipelines, cryptographic erasure becomes impossible.
  </p>

  <h3>4.3 Multimodal Surveillance and Biometric Risk</h3>
  <p>
    Directly uploading official identity cards, academic grade sheets, or uncropped facial images transmits raw biometric embeddings and high-resolution document artifacts to external vision-language models without explicit bounding or metadata sanitization.
  </p>

  <h2>5. The MEMVERSE Solution Architecture</h2>
  <p>
    MEMVERSE addresses these threat vectors through a client-governed security framework:
  </p>
  <ul>
    <li><strong>Synchronous 12-Stage Pipeline:</strong> Every inbound request undergoes entity detection, injection analysis, policy transformation, and egress gatekeeping prior to model dispatch.</li>
    <li><strong>Dynamic Generalization Matrix:</strong> Automatically transforms exact values into categorical ranges (e.g., names to roles, exact numbers to bands, cities to geographic regions).</li>
    <li><strong>Scoped Memory Passports:</strong> Issues cryptographic access tokens with strict Time-To-Live (TTL) limits, purpose registration, and immediate revocation capabilities.</li>
    <li><strong>Cryptographic Auditability:</strong> Records all transactions in a SHA-256 hash-linked ledger, providing verifiable mathematical proofs of data transformation.</li>
  </ul>

  <h2>6. Conclusion</h2>
  <p>
    MEMVERSE demonstrates that high-utility personalization and robust privacy preservation are compatible. By enforcing strict contextual boundaries, MEMVERSE provides a production-ready blueprint for trustworthy, privacy-compliant AI deployments.
  </p>

  <div class="footer-line">
    <span>MEMVERSE Problem Definition & Technical Rationale</span>
    <span>Author: Satvik Kesarwani</span>
  </div>

</body>
</html>
"""

HTML_DOC2 = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>MEMVERSE - System Architecture and User Flow</title>
  <style>{FORMAL_CSS}</style>
</head>
<body>

  <div class="doc-header">
    <div>
      <div class="institution-tag">SYSTEM ARCHITECTURE SPECIFICATION</div>
      <div style="font-size: 13pt; font-weight: 700; color: #111827; margin-top: 2px;">MEMVERSE</div>
    </div>
    <div class="doc-meta">
      Document ID: ARCH-2026-02<br>
      Date: September 4, 2026
    </div>
  </div>

  <h1>MEMVERSE: Architecture, Pipeline & Operational Workflow</h1>
  <div class="doc-subtitle">Detailed Technical Specification of the Zero-Trust Gateway, 12-Stage Pipeline, and Multimodal Data Flow</div>

  <h2>1. System Architecture Overview</h2>
  <p>
    The MEMVERSE platform is structured as a three-tier decoupled architecture:
  </p>
  <ul>
    <li><strong>Client Layer (Frontend):</strong> A single-page application built with React and Vite, hosting the conversational interface, Identity Vault, biometric scanner, and real-time security trace inspection drawer.</li>
    <li><strong>Security Gateway Layer (Backend):</strong> A high-throughput FastAPI service hosting the 12-stage security engine, policy evaluator, cryptographic key manager, and Merkle-style hash ledger.</li>
    <li><strong>External Model Layer (Inference Engine):</strong> Cloud-hosted NVIDIA NIM endpoints (e.g., Llama-3.3-70B-Instruct, Nemotron) that receive strictly sanitized payloads and return streaming responses.</li>
  </ul>

  <h2>2. The 12-Stage Zero-Trust Execution Pipeline</h2>
  <p>
    Each user interaction executes synchronously across twelve discrete processing stages:
  </p>

  <table>
    <thead>
      <tr>
        <th style="width: 8%;">Stage</th>
        <th style="width: 27%;">Component</th>
        <th style="width: 65%;">Operational Specification</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>01</strong></td>
        <td>Request Ingestion</td>
        <td>Captures inbound prompt, session token, purpose declaration, and target model identifier.</td>
      </tr>
      <tr>
        <td><strong>02</strong></td>
        <td>Sensitive Entity Detection</td>
        <td>Scans input for Named Entities (NER) and regex patterns across PII categories (names, emails, IDs, locations).</td>
      </tr>
      <tr>
        <td><strong>03</strong></td>
        <td>Poisoning & Injection Defense</td>
        <td>Evaluates prompt against heuristic and semantic injection patterns to detect instruction override attempts.</td>
      </tr>
      <tr>
        <td><strong>04</strong></td>
        <td>Memory Retrieval</td>
        <td>Queries local encrypted memory store for candidate records associated with the user profile.</td>
      </tr>
      <tr>
        <td><strong>05</strong></td>
        <td>Policy Matrix Evaluation</td>
        <td>Applies policy matrix v1.4 to determine field-level actions (SUPPRESS, GENERALIZE, REDACT, or ALLOW).</td>
      </tr>
      <tr>
        <td><strong>06</strong></td>
        <td>Context Transformation</td>
        <td>Replaces detected sensitive tokens with coarse-grained categorical bands and generalized identifiers.</td>
      </tr>
      <tr>
        <td><strong>07</strong></td>
        <td>Passport Scope Verification</td>
        <td>Validates memory passport integrity hash, consent status, destination binding, and TTL expiration.</td>
      </tr>
      <tr>
        <td><strong>08</strong></td>
        <td>Approved Context Synthesis</td>
        <td>Assembles the final sanitized context block and system prompt. Raw data is excluded.</td>
      </tr>
      <tr>
        <td><strong>09</strong></td>
        <td>Egress Validation Gate</td>
        <td>Performs final automated boundary scan to guarantee zero prohibited fields exit the trusted domain.</td>
      </tr>
      <tr>
        <td><strong>10</strong></td>
        <td>External Model Execution</td>
        <td>Dispatches sanitized prompt to NVIDIA NIM via secure SSE transport and receives streaming tokens.</td>
      </tr>
      <tr>
        <td><strong>11</strong></td>
        <td>Response Ingress Validation</td>
        <td>Inspects incoming completion tokens to prevent memory leakage or malicious output reflection.</td>
      </tr>
      <tr>
        <td><strong>12</strong></td>
        <td>Audit Ledger Receipt</td>
        <td>Appends a cryptographic SHA-256 receipt containing timestamp, event hash, and previous hash link.</td>
      </tr>
    </tbody>
  </table>

  <div class="page-break"></div>

  <h2>3. Multimodal Ingestion Specifications</h2>

  <h3>3.1 Structured Document Processing (PDF / DOCX)</h3>
  <p>
    When a document (e.g., an academic grade sheet or employment certificate) is uploaded:
  </p>
  <ul>
    <li>The server parses text and tabular data using PyPDF and PDFPlumber.</li>
    <li>Automated pattern recognizers detect registration numbers, marks, and signatures.</li>
    <li>Sensitive values are generalized into contextual performance tiers before ingestion into the user's active memory passport.</li>
  </ul>

  <h3>3.2 Biometric Face Image Ingestion</h3>
  <p>
    When photographic inputs are provided:
  </p>
  <ul>
    <li>Facial landmark detection executes locally in the client browser using <code>face-api.js</code>.</li>
    <li>The client presents an explicit consent confirmation dialog displaying the cropped region.</li>
    <li>EXIF data, GPS coordinates, and raw camera metadata are stripped before any downstream processing.</li>
  </ul>

  <h2>4. End-to-End User Operational Flow</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 15%;">Phase</th>
        <th style="width: 35%;">User Action</th>
        <th style="width: 50%;">System Execution & Output</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>1. Setup</strong></td>
        <td>Connects to platform or uploads identity document / image</td>
        <td>Generates AES-256 encrypted memory records and issues active Memory Passport with TTL.</td>
      </tr>
      <tr>
        <td><strong>2. Interaction</strong></td>
        <td>Enters prompt in conversational interface</td>
        <td>Gateway executes 12-stage pipeline, redacts PII, and constructs approved context block.</td>
      </tr>
      <tr>
        <td><strong>3. Response</strong></td>
        <td>Receives streaming model completion</td>
        <td>NVIDIA NIM generates tailored output using sanitized background without access to raw PII.</td>
      </tr>
      <tr>
        <td><strong>4. Inspection</strong></td>
        <td>Opens Security Trace Drawer</td>
        <td>Visualizes stage execution timings, transformed field mappings, and egress payload boundaries.</td>
      </tr>
      <tr>
        <td><strong>5. Audit</strong></td>
        <td>Views Event Ledger</td>
        <td>Inspects tamper-evident SHA-256 receipts verifying provenance and non-repudiation.</td>
      </tr>
    </tbody>
  </table>

  <h2>5. Security Guarantees</h2>
  <ol>
    <li><strong>Client-Model Isolation:</strong> The frontend client never possesses or transmits external model API keys.</li>
    <li><strong>Fail-Closed Design:</strong> Any failure in passport validation, consent check, or egress scanning immediately aborts the model call.</li>
    <li><strong>Cryptographic Non-Repudiation:</strong> Hash-linked ledger chains ensure that all memory access events are permanently auditable and tamper-evident.</li>
  </ol>

  <div class="footer-line">
    <span>MEMVERSE System Architecture Specification</span>
    <span>Author: Satvik Kesarwani</span>
  </div>

</body>
</html>
"""

def generate_pdfs():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        
        # 1. Submission Overview (1 Page)
        page1 = browser.new_page()
        page1.set_content(HTML_ONE_PAGE)
        pdf1_path = os.path.join(OUTPUT_DIR, "MEMVERSE_Submission_Summary.pdf")
        page1.pdf(path=pdf1_path, format="A4", print_background=True)
        print(f"Generated: {pdf1_path}")
        
        # 2. Problem Definition & Need (2 Pages)
        page2 = browser.new_page()
        page2.set_content(HTML_DOC1)
        pdf2_path = os.path.join(OUTPUT_DIR, "MEMVERSE_Why_This_Project_Is_Needed.pdf")
        page2.pdf(path=pdf2_path, format="A4", print_background=True)
        print(f"Generated: {pdf2_path}")
        
        # 3. Architecture & User Flow (3 Pages)
        page3 = browser.new_page()
        page3.set_content(HTML_DOC2)
        pdf3_path = os.path.join(OUTPUT_DIR, "MEMVERSE_Architecture_and_User_Flow.pdf")
        page3.pdf(path=pdf3_path, format="A4", print_background=True)
        print(f"Generated: {pdf3_path}")
        
        browser.close()

if __name__ == "__main__":
    generate_pdfs()
