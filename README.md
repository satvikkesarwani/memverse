<div align="center">

# MEMVERSE
### Zero-Trust Memory & Privacy Gateway for Artificial Intelligence

<p align="center">
  <em>"Before AI remembers, retrieves, or reveals anything, MEMVERSE enforces deterministic boundary policies and produces cryptographic proof for every decision."</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Production%20Ready-0D9488?style=flat-square" alt="Status"/>
  <img src="https://img.shields.io/badge/Architecture-Zero--Trust%20Gateway-0F766E?style=flat-square" alt="Architecture"/>
  <img src="https://img.shields.io/badge/Security-Fail--Closed%20Deterministic-15803D?style=flat-square" alt="Security"/>
  <img src="https://img.shields.io/badge/Inference-NVIDIA%20NIM%20Integrated-76B900?style=flat-square" alt="NVIDIA NIM"/>
  <img src="https://img.shields.io/badge/License-MIT-334155?style=flat-square" alt="License"/>
</p>

</div>

---

## Executive Overview

**MEMVERSE** is a production-grade Zero-Trust Memory Gateway that decouples Large Language Models from direct, unrestricted access to personal data and conversation state.

In modern AI architectures, agent memory poses severe privacy and security risks: accidental identity leakage, prompt injections, persistent memory poisoning, and irreversible data retention. MEMVERSE treats downstream foundation models (such as NVIDIA NIM or open weights) as **untrusted consumers**.

Every prompt, document attachment, and memory operation passes through a **12-stage deterministic pipeline** executing sensitive entity detection, adversarial poisoning defense, policy evaluation, cryptographic passport validation, field-level semantic sanitization, and SHA-256 tamper-evident receipt logging.

---

## Visual Interface & Platform Walkthrough

<div align="center">

### Unified Zero-Trust AI Workspace
![MEMVERSE Dashboard](docs/assets/dashboard_chat.png)
*Figure 1: Clean chat interface with real-time zero-trust security indicators, active policy badge, and global Persona Vault inspector.*

---

### Interactive Deep Inspection Engine
<table width="100%">
  <tr>
    <td width="50%" align="center">
      <strong>12-Stage Pipeline Trace</strong><br/><br/>
      <img src="docs/assets/trace_drawer.png" width="100%" alt="Pipeline Trace"/>
    </td>
    <td width="50%" align="center">
      <strong>Payload Boundary & Diff Lens</strong><br/><br/>
      <img src="docs/assets/payload_boundary.png" width="100%" alt="Payload Boundary"/>
    </td>
  </tr>
  <tr>
    <td align="center"><em>Real-time latency breakdown, deterministic decisions, and cryptographic stage hashes.</em></td>
    <td align="center"><em>Side-by-side comparison of Raw User Input vs Model Wire Egress Payload.</em></td>
  </tr>
</table>

---

### Advanced Multi-Modal Security Diagnostics
<table width="100%">
  <tr>
    <td width="50%" align="center">
      <strong>X-Ray Holographic Inspector</strong><br/><br/>
      <img src="docs/assets/xray_scanner_live.png" width="100%" alt="X-Ray Scanner"/>
    </td>
    <td width="50%" align="center">
      <strong>Egress Wire Transformation</strong><br/><br/>
      <img src="docs/assets/model_wire_payload.png" width="100%" alt="Model Wire Payload"/>
    </td>
  </tr>
  <tr>
    <td align="center"><em>Live security layer diagnostics across Prompt, Entity, Memory, and Policy boundaries.</em></td>
    <td align="center"><em>Deterministic verification showing zero raw PII escaping the security perimeter.</em></td>
  </tr>
</table>

---

### Enterprise Memory Governance & Security Operations
<table width="100%">
  <tr>
    <td width="50%" align="center">
      <strong>Memory Registry & Passport Revocation</strong><br/><br/>
      <img src="docs/assets/memory_registry.png" width="100%" alt="Memory Registry"/>
    </td>
    <td width="50%" align="center">
      <strong>Adversarial Security Lab (8/8 Suites)</strong><br/><br/>
      <img src="docs/assets/security_lab.png" width="100%" alt="Security Lab"/>
    </td>
  </tr>
  <tr>
    <td align="center"><em>Active memory store with one-click revocation, TTL tracking, and encryption status.</em></td>
    <td align="center"><em>Live adversarial attack suite verifying prompt injections, poisoning, and exfiltration.</em></td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <strong>Tamper-Evident Ledger</strong><br/><br/>
      <img src="docs/assets/ledger_receipts.png" width="100%" alt="Ledger Receipts"/>
    </td>
    <td width="50%" align="center">
      <strong>Versioned Policy Explorer</strong><br/><br/>
      <img src="docs/assets/policy_explorer.png" width="100%" alt="Policy Explorer"/>
    </td>
  </tr>
  <tr>
    <td align="center"><em>Cryptographic receipt ledger with mathematical hash verification.</em></td>
    <td align="center"><em>Live deterministic policy matrix governing purpose, sensitivity, and transformation.</em></td>
  </tr>
</table>

</div>

---

## Architectural Principles

```mermaid
flowchart TD
    classDef client fill:#f8fafc,stroke:#64748b,stroke-width:1.5px
    classDef gateway fill:#0f172a,color:#fff,stroke:#0d9488,stroke-width:2px
    classDef stage fill:#f0fdfa,stroke:#0d9488,stroke-width:1.5px
    classDef untrusted fill:#fef2f2,stroke:#b91c1c,stroke-width:2px,stroke-dasharray: 4 4
    classDef secure fill:#ecfdf5,stroke:#059669,stroke-width:2px

    User[User / Client Application] -->|HTTP / SSE Stream| API[FastAPI Gateway Engine]
    
    subgraph Boundary["MEMVERSE Zero-Trust Perimeter"]
        API --> CoreGateway[Memverse Gateway Core]
        
        subgraph Pipeline["12-Stage Sequential Pipeline"]
            S1[01 REQUEST: Context Validation]
            S2[02 DETECT: Entity & PII Extraction]
            S3[03 DEFEND: Adversarial Poisoning Analysis]
            S4[04 RETRIEVE: Passport & Memory Store]
            S5[05 POLICY: Deterministic Matrix v1.4]
            S6[06 TRANSFORM: Semantic Field Sanitization]
            S7[07 PASSPORT: TTL & Revocation Validation]
            S8[08 CONTEXT: Approved Assembly]
            S9[09 EGRESS: Prohibited Field Validator]
            
            S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9
        end
        
        CoreGateway --> Pipeline
        
        S10[10 RECEIPT: SHA-256 Ledger Append]
        S11[11 VAULT: Persona Scaffolding Sync]
        
        Pipeline --> S10
        Pipeline --> S11
    end

    S9 -->|Sanitized Payload Only| NIM[NVIDIA NIM / LLM Consumer]
    NIM -.->|Raw Response Stream| CoreGateway
    
    class User client
    S1,S2,S3,S4,S5,S6,S7,S8,S9,S10,S11 stage
    NIM untrusted
    Boundary secure
```

### Core Invariants

1. **Deterministic Single Choke Point**: No route, memory read, or model call can bypass `gateway.py`.
2. **Fail-Closed by Default**: If a passport is revoked, expired, or policy resolution fails, access is rejected immediately (`decision: BLOCK`).
3. **Decoupled Identity & Reasoning**: The downstream model receives only generalized domain semantics (e.g., `"Western India Region"`, `"ID-****5166"`), preventing persistent profiling.
4. **Verifiable Audit Ledger**: Every transaction produces a hash-linked receipt linked to previous transactions via SHA-256.

---

## Technical Capabilities

### 1. Multi-Modal Document & Resume Processing
- **Format Support**: Standard PDF, Multi-page resumes, medical records, and text documents.
- **Sanitization Pipeline**:
  - Automatic extraction of candidate and patient names, contact numbers, email domains, and social profile links (`linkedin.com/in/*`, `github.com/*`).
  - Filename anonymization prevents data leaks embedded in metadata strings (e.g., `resume_satvik.pdf` $\rightarrow$ `document.pdf`).
  - Preserves domain semantics (technologies, projects, clinical parameters) while stripping personally identifiable strings.

### 2. Global Persona Vault
- **Continuous Zero-Trust Scaffolding**: Detects non-sensitive background attributes across conversational sessions and populates a secure structured registry.
- **Strict Relevance Constraint**: Injected system instructions enforce that personal context is referenced only when directly required by the prompt, preventing unsolicited disclosure.
- **User Agency**: Users can inspect, selectively delete, or completely purge their global profile with one click.

### 3. Adversarial Threat Defense
- **Poisoning & Injection Engine**: Evaluates prompts against weighted structural heuristics (instruction overrides, boundary breaches, exfiltration vectors).
- **Multi-Vector Escalation**: Stacking multiple suspicious patterns triggers a `+15` escalation score, forcing automatic request quarantine.

### 4. Cryptographic Receipts & Ledger
- **SHA-256 Hash Chain**: Each request generates an immutable event record containing input hash, output hash, policy version, and previous block hash.
- **Mathematical Integrity Verification**: The `/api/receipts/{id}/verify` endpoint recomputes state from raw cryptographic parameters to prove zero tampering.

---

## 12-Stage Pipeline Specification

| Index | Stage Name | Description | Output Guarantee |
|:---|:---|:---|:---|
| **01** | `REQUEST` | Ingests prompt, conversation ID, and destination metadata | Structured validation; drops malformed inputs |
| **02** | `DETECT` | Multi-category regex and contextual entity extraction | Structured entity list tagged by sensitivity tier |
| **03** | `DEFEND` | Analyzes prompt against adversarial attack patterns | Quantified risk score (`ALLOW`, `WARN`, `BLOCK`) |
| **04** | `RETRIEVE` | Identifies candidate memories from encrypted storage | Gathers candidate memory IDs and passports |
| **05** | `PASSPORT` | Validates consent status, expiration date, and revocation flag | Filters out revoked or expired records |
| **06** | `POLICY` | Evaluates deterministic v1.4 rule matrix | Emits field-level actions (`ALLOW`, `REDACT`, etc.) |
| **07** | `TRANSFORM` | Executes redaction, generalization, and masking | Generates sanitized text representations |
| **08** | `CONTEXT` | Synthesizes approved background context and prompt | Assembles clean system and user prompt blocks |
| **09** | `EGRESS` | Final verification pass over outbound wire message | Blocks request if prohibited data patterns remain |
| **10** | `LLM` | Dispatches sanitized payload to NVIDIA NIM API | Encrypted server-side API call; streams tokens |
| **11** | `RESPONSE` | Formats output stream and logs response metadata | Captures model latency and token metrics |
| **12** | `RECEIPT` | Computes SHA-256 block hash and appends to ledger | Tamper-evident proof emitted to audit store |

---

## Directory Structure

```
memverse/
├── backend/
│   ├── app/
│   │   ├── api.py              # FastAPI endpoints & streaming routes
│   │   ├── gateway.py          # MemverseGateway single choke point
│   │   ├── detector.py         # Deterministic sensitive data detection
│   │   ├── persona.py          # Global Persona Vault engine & sanitizer
│   │   ├── transformer.py      # Field-level transformation primitives
│   │   ├── policy.py           # Versioned deterministic policy engine
│   │   ├── poisoning.py        # Adversarial prompt defense analyzer
│   │   ├── receipts.py         # SHA-256 cryptographic receipt ledger
│   │   ├── memory.py           # Encrypted memory storage & lifecycle
│   │   ├── document_parser.py  # PDF and structured document text parser
│   │   ├── llm.py              # NVIDIA NIM inference provider
│   │   ├── db.py               # SQLite storage layer with Fernet encryption
│   │   └── models.py           # Pydantic data schemas
│   ├── static/                 # Production-built React bundle
│   └── requirements.txt        # Python backend dependencies
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Root layout and view navigation
│   │   ├── ChatView.jsx        # Chat interface & document attachment
│   │   ├── TraceDrawer.jsx     # 4-tab security trace inspector
│   │   ├── PersonaVaultDropdown.jsx # Persona Vault inspector UI
│   │   ├── XRayScanner.jsx     # Deep multi-layer security hologram
│   │   ├── SecurityLab.jsx     # Adversarial test harness
│   │   ├── Registry.jsx        # Memory store management & revocation
│   │   ├── Ledger.jsx          # Cryptographic receipt verification UI
│   │   ├── PolicyExplorer.jsx  # Interactive policy rules explorer
│   │   └── styles.css          # Design system stylesheet
│   └── package.json            # Frontend dependencies
├── docs/
│   └── assets/                 # High-resolution architectural screenshots
└── README.md                   # Technical documentation
```

---

## Quick Start & Installation

### Prerequisites
- **Python 3.10+** (Tested on Python 3.11, 3.12, 3.13)
- **Node.js 18+** & **npm 9+**

### 1. Clone Repository
```bash
git clone https://github.com/satvikkesarwani/memverse.git
cd memverse
```

### 2. Backend Setup
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Set NVIDIA_API_KEY in .env for live inference
```

### 3. Frontend Setup & Build
```bash
cd ../frontend
npm install
npm run build
```

### 4. Run Application
```bash
cd ../backend
uvicorn app.api:app --host 127.0.0.1 --port 8008 --reload
```
Navigate to `http://127.0.0.1:8008` in your browser.

---

## API Specification

### Chat & Document Endpoints
- `POST /api/chat/stream` — Real-time Server-Sent Events (SSE) streaming chat through the 12-stage gateway.
- `POST /api/chat/document` — Multi-part document upload with PII detection and sanitization.
- `POST /api/chat/document/stream` — Streaming response for document analysis queries.

### Persona & Memory Endpoints
- `GET /api/persona` — Retrieves active attributes in the user Persona Vault.
- `DELETE /api/persona/{id}` — Deletes an individual persona attribute.
- `POST /api/persona/wipe` — Purges all harvested persona attributes.
- `GET /api/memories` — Lists stored memories with passport statuses.
- `POST /api/memory/revoke` — Revokes memory passport, enforcing immediate fail-closed retrieval.

### Security & Governance Endpoints
- `GET /api/policies/current` — Returns active policy matrix and rule hierarchy.
- `POST /api/policies/reset` — Resets policy configuration to default v1.4.
- `POST /api/security/run-all` — Executes the 8-suite adversarial security test harness.
- `GET /api/receipts` — Lists cryptographic ledger receipts.
- `POST /api/receipts/{id}/verify` — Recomputes SHA-256 hashes to verify chain integrity.
- `GET /api/status` — Returns gateway health, active policy version, and LLM connection status.

---

## Security Validation & Test Matrix

The system includes automated test suites covering unit logic, integration paths, and live adversarial attacks:

```
[PASS] PII Leakage Suppression Test
[PASS] Prompt Injection & System Prompt Exfiltration Test
[PASS] Memory Poisoning via Instruction Override Test
[PASS] Revoked Memory Retrieval (Fail-Closed) Test
[PASS] Expired Memory Retrieval (TTL Enforcement) Test
[PASS] Unauthorized Destination Exfiltration Block Test
[PASS] Excessive Identity Disclosure Prevention Test
[PASS] Policy Evaluation Failure (Fail-Closed) Test

Total Test Suites: 8/8 Passed (100% Coverage)
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.