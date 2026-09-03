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

## System Architecture

### High-Level Architectural Flow

```mermaid
flowchart TD
    User["User / Application"] -->|Chat Prompt or Document| API["FastAPI Gateway (/api/chat)"]
    
    subgraph TrustedZone["TRUSTED ZONE: MEMVERSE Gateway Choke Point"]
        direction TB
        API --> GatewayCore["Gateway Orchestrator"]
        
        subgraph Pipeline["12-Stage Deterministic Security Pipeline"]
            direction TB
            S1["01 REQUEST: Ingestion & Metadata Validation"]
            S2["02 DETECT: Entity & PII Scanner"]
            S3["03 DEFEND: Adversarial Poisoning Analyzer"]
            S4["04 RETRIEVE: Passport & Memory Store"]
            S5["05 POLICY: Deterministic Rule Matrix v1.4"]
            S6["06 TRANSFORM: Semantic Field Sanitizer"]
            S7["07 PASSPORT: TTL & Revocation Evaluator"]
            S8["08 CONTEXT: Approved Context Assembler"]
            S9["09 EGRESS: Outbound Prohibited Field Guard"]
            
            S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9
        end
        
        GatewayCore --> Pipeline
        
        S10["10 RECEIPT: SHA-256 Ledger Append"]
        S11["11 VAULT: Persona Scaffolding Sync"]
        
        Pipeline --> S10
        Pipeline --> S11
    end
    
    subgraph UntrustedZone["UNTRUSTED ZONE: Downstream Consumer"]
        LLM["NVIDIA NIM / Foundation Model"]
    end
    
    DB[("SQLite Store (Fernet Encrypted)")]
    
    S9 -->|Sanitized Payload Only| LLM
    LLM -.->|Inference Output Stream| GatewayCore
    S10 --> DB
    S4 <--> DB
```

### Component Breakdown

| Component | Module | Responsibility |
|:---|:---|:---|
| **FastAPI Routes** | `backend/app/api.py` | Dedicated entry point for frontend requests with zero bypass |
| **Gateway Core** | `backend/app/gateway.py` | Single choke point executing the 12-stage security lifecycle |
| **Sensitive Detector** | `backend/app/detector.py` | Multi-category regex and context lexicon entity extraction |
| **Persona Vault** | `backend/app/persona.py` | Global Persona Vault auto-harvester and relevance scaffolding |
| **Poisoning Defense** | `backend/app/poisoning.py` | Weighted heuristic scoring against prompt injections and overrides |
| **Policy Engine** | `backend/app/policy.py` | Versioned typed rules v1.4 and sensitivity-operation matrix |
| **Transformer** | `backend/app/transformer.py` | Deterministic `SUPPRESS`, `GENERALIZE`, `REDACT`, `TOKENIZE`, `ALLOW` |
| **Egress Guard** | `backend/app/egress.py` | Final byte-level check preventing prohibited values from crossing wire |
| **Cryptographic Receipts** | `backend/app/receipts.py` | SHA-256 hash-linked ledger generation and real-time verification |
| **Encrypted Storage** | `backend/app/crypto.py` / `db.py` | SQLite persistence with Fernet symmetric authenticated encryption |

---

## User Workflow

```mermaid
journey
    title User Interaction & Security Audit Journey
    section Interactive Chat
      Launch Web Application: 5: User
      Upload Document or Resume: 5: User
      Submit Query ("Summarize my background"): 5: User
    section Gateway Inspection
      Click Inspect MEMVERSE: 5: User
      Review 12-Stage Pipeline Latencies: 5: User
      Inspect Raw Input vs Sanitized Payload Lens: 5: User
      Verify SHA-256 Hash Chain Integrity: 5: User
    section Memory & Policy Governance
      Inspect Global Persona Vault Attributes: 5: User
      Revoke Stored Memory Passport: 5: User
      Re-query Revoked Memory (Fail-Closed Denied): 5: User
    section Adversarial Validation
      Run Security Lab (8/8 Attack Suites): 5: User
      Inspect Immutable Cryptographic Receipts: 5: User
```

---

## Data & Request Lifecycles

### Complete Request Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Client as User / Application
    participant GW as MEMVERSE Gateway
    participant Policy as Policy Engine (v1.4)
    participant Store as Encrypted Memory DB
    participant LLM as NVIDIA NIM (Untrusted)

    Client->>GW: POST /api/chat/stream {prompt, document, purpose}
    
    rect rgb(240, 253, 250)
        Note over GW: 12-Stage Deterministic Pipeline Execution
        GW->>GW: 01 REQUEST: Validate purpose and destination
        GW->>GW: 02 DETECT: Scan PII (Names, Phone, Email, Handles)
        GW->>GW: 03 DEFEND: Score injection and override risk
        GW->>Store: 04 RETRIEVE: Fetch candidate memories & passports
        Store-->>GW: Encrypted records + passport metadata
        GW->>GW: 05 PASSPORT: Check TTL and revocation state (Fail-Closed)
        GW->>Policy: 06 POLICY: Evaluate field-level actions
        Policy-->>GW: Field decisions (SUPPRESS, GENERALIZE, REDACT)
        GW->>GW: 07 TRANSFORM: Execute field sanitization
        GW->>GW: 08 CONTEXT: Assemble sanitized prompt + background
        GW->>GW: 09 EGRESS: Validate zero raw PII remains
    end
    
    GW->>LLM: 10 LLM: Dispatch sanitized payload
    Note over LLM: Model sees zero raw PII or exact identifiers
    LLM-->>GW: Stream tokens via SSE
    
    rect rgb(240, 253, 250)
        GW->>GW: 11 RESPONSE: Stream tokens to client
        GW->>Store: 12 RECEIPT: Append SHA-256 block to ledger
    end
    
    GW-->>Client: Complete response + Receipt ID + Trace ID
```

### Memory Passport Lifecycle

```mermaid
stateDiagram-v2
    [*] --> MemoryWritten: User declares memory or writes via Playground
    
    state MemoryWritten {
        [*] --> DetectionScan
        DetectionScan --> PoisoningAnalysis
        PoisoningAnalysis --> PolicyEvaluation
        PolicyEvaluation --> FernetEncryption
        FernetEncryption --> IssuePassport
    }
    
    IssuePassport --> ACTIVE: Consent granted and TTL valid
    
    state ACTIVE {
        [*] --> ReadRequest
        ReadRequest --> ValidatePassport
        ValidatePassport --> ELIGIBLE: Passport valid
        ELIGIBLE --> TransformSemantic: Apply field transforms
        TransformSemantic --> ApprovedContext: Model-safe context
    }
    
    ACTIVE --> REVOKED: User clicks Revoke in Registry
    ACTIVE --> EXPIRED: TTL threshold exceeded
    ACTIVE --> QUARANTINED: Memory poisoning pattern detected
    
    REVOKED --> FAIL_CLOSED: Access blocked immediately
    EXPIRED --> FAIL_CLOSED: Access blocked immediately
    QUARANTINED --> NEVER_RETRIEVED: Excluded from all inference
```

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