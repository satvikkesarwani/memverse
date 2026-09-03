// How MEMVERSE Works — Interactive Zero-Trust Security Architecture
import React, { useState } from 'react'
import { Badge, ShieldIcon } from './ui'

const STEPS = [
  { id: 'app', num: '01', title: 'Application Layer', sub: 'React Chat UI & Document Upload', tag: 'INPUT', badge: 'info' },
  { id: 'gateway', num: '02', title: 'MEMVERSE Gateway', sub: 'Single Choke Point Enforcement', tag: 'CORE', badge: 'ok' },
  { id: 'detect', num: '03', title: 'Sensitive Data Detector', sub: 'Deterministic Scan (PII, Medical, Financial)', tag: 'DETECT', badge: 'accent' },
  { id: 'defend', num: '04', title: 'Poisoning & Injection Defense', sub: 'Pattern-Weighted Scorer & Jailbreak Interceptor', tag: 'DEFENSE', badge: 'blocked' },
  { id: 'policy', num: '05', title: 'Policy-as-Code Engine', sub: 'Versioned Typed Contract (v1.4)', tag: 'GOVERNANCE', badge: 'warn' },
  { id: 'passport', num: '06', title: 'Memory Passport Validation', sub: 'Consent, Purpose, TTL & Revocation Check', tag: 'CREDENTIAL', badge: 'info' },
  { id: 'transform', num: '07', title: 'Data Transformer', sub: 'Suppress, Generalize, Redact, Tokenize', tag: 'PRIVACY', badge: 'accent' },
  { id: 'egress', num: '08', title: 'Egress Security Gate', sub: 'Final Outbound Payload Re-scan', tag: 'BOUNDARY', badge: 'blocked' },
  { id: 'approved', num: '09', title: 'Approved Context Assembly', sub: 'Sanitized Representation Only', tag: 'RELEASE', badge: 'ok' },
  { id: 'llm', num: '10', title: 'External Model (NVIDIA NIM)', sub: 'Untrusted Downstream Consumer', tag: 'DOWNSTREAM', badge: 'default' },
]

const EXPLANATIONS = {
  app: {
    overview: 'A zero-trust client interface where users interact with AI or submit medical diagnostic reports (PDF).',
    details: 'Users never talk to external models directly. Every prompt, chat query, or uploaded document is routed through the local MEMVERSE gateway.',
    invariant: 'Direct model egress is physically impossible from the frontend.',
    sample: '{ "prompt": "Can you find hospitals near Sector 137, Noida?", "purpose": "answer_query", "destination": "nvidia" }'
  },
  gateway: {
    overview: 'The mandatory architectural choke point governing all read, write, retrieve, revoke, and learning operations.',
    details: 'Every memory operation and model-bound payload must pass through the gateway pipeline. The gateway executes deterministic validation rules and fails closed upon any security exception.',
    invariant: 'Nothing enters the database or reaches the model without a signed security receipt.',
    sample: 'MemverseGateway.process_chat(prompt, conversation_id, purpose, destination)'
  },
  detect: {
    overview: 'Multi-pattern deterministic scanner for sensitive data across Indian and global regulatory domains.',
    details: 'Detects personal names, age, exact addresses (sectors, pincodes, cities), phone numbers, email addresses, PAN cards, Aadhaar numbers, UPI IDs, organizations, medications, and medical diagnostic header metadata.',
    invariant: 'Zero sensitive entity escapes unclassified classification.',
    sample: 'DetectedEntity(entity="Sector 137, Noida", type="location", sensitivity="HIGH", confidence=0.95)'
  },
  defend: {
    overview: 'Weighted pattern-scoring engine that defends against memory poisoning, prompt injection, and adversarial identity exfiltration.',
    details: 'Calculates risk scores based on malicious instructions (system overrides, concealment demands, privilege escalation, unauthorized tool calls). Inputs scoring HIGH (≥50) or CRITICAL (≥80) fail closed immediately.',
    invariant: 'Poisoned instructions are quarantined or blocked before they can influence persistent memory or model context.',
    sample: 'PoisoningResult(risk_score=80, risk_level="CRITICAL", action="BLOCK", reason="identity transfer demand")'
  },
  policy: {
    overview: 'Declarative, versioned policy-as-code engine (v1.4) executing rule sets and field-level strategy matrices.',
    details: 'Evaluates requests based on purpose, destination, sensitivity, and passport state. Field strategies (SUPPRESS, GENERALIZE, REDACT, ALLOW) determine how each sensitive data type is handled.',
    invariant: 'Every policy decision is deterministic, reproducible, and verifiable.',
    sample: 'field_strategy: { "location": { "on_transform": "GENERALIZE" }, "identity": { "on_transform": "SUPPRESS" } }'
  },
  passport: {
    overview: 'Cryptographically-linked credential governing each memory item: purpose, consent, TTL expiry, and revocation state.',
    details: 'Before memory retrieval is permitted, the gateway validates that the passport is ACTIVE, within TTL, matches the declared purpose, and has not been revoked. Quarantined or revoked passports fail closed.',
    invariant: 'No memory is released without an ACTIVE, valid Memory Passport.',
    sample: 'MemoryPassport(memory_id="mem_84f91c", revocation_state="ACTIVE", ttl_days=30, integrity_hash="a1b2c3...")'
  },
  transform: {
    overview: 'Transformation engine that converts sensitive raw entities into mathematically safe, privacy-preserving representations.',
    details: 'Applies field transformations: SUPPRESS suppresses identity tokens, GENERALIZE converts exact locations into broad regions (e.g., Sector 137, Noida → Noida (Northern India)), REDACT masks contact numbers, and Differential Privacy (ε) adds Laplace noise for analytical exports.',
    invariant: 'Raw sensitive values are withheld from downstream model payloads.',
    sample: '"Sector 137, Noida" → "Noida (Northern India)" | "Alex, 24 years old" → "Adult (20-29)"'
  },
  egress: {
    overview: 'The final zero-trust outbound firewall before anything crosses the network boundary.',
    details: 'The compiled message payload is completely re-scanned for any prohibited raw memory values or unredacted PII. If a prohibited field is detected, the entire model request is BLOCKED.',
    invariant: 'Egress gate fails closed — violation results in BLOCK, never a silent pass.',
    sample: 'EgressResult(status="PASS", prohibited_fields=0, checks=["NO_RAW_PII", "DESTINATION_APPROVED"])'
  },
  approved: {
    overview: 'The strictly approved context block — the ONLY memory representation the downstream model is permitted to see.',
    details: 'Contains only generalized facts and policy-approved context. Raw private memory, system instructions, and patient identifying headers are completely excluded.',
    invariant: 'What the model sees is provably restricted to the approved context assembly.',
    sample: 'APPROVED MEMORY CONTEXT:\n- Location: Noida (Northern India)\n- Condition: Diagnostic parameters within report'
  },
  llm: {
    overview: 'The external model (e.g., NVIDIA NIM Nemotron) treated as an untrusted downstream consumer.',
    details: 'The model is called server-side via authenticated API keys. The model cannot read raw memory, write to storage, or alter gateway security policies. Its responses are captured and signed into the ledger.',
    invariant: 'The LLM has zero direct storage access and zero policy authority.',
    sample: 'NVIDIA NIM Nemotron-3.5-Lightning (latency: 420ms, payload_hash: "9f83a2...")'
  },
}

export default function Architecture() {
  const [sel, setSel] = useState('gateway')
  const cur = EXPLANATIONS[sel] || EXPLANATIONS.gateway
  const curStep = STEPS.find(s => s.id === sel) || STEPS[1]

  return (
    <div className="page">
      <div className="page-inner">
        <div className="page-head">
          <div>
            <div className="page-title">How MEMVERSE Works</div>
            <div className="page-sub">
              Interactive zero-trust architectural blueprint. The downstream model never receives memory directly — every request passes through the 10-stage security membrane.
            </div>
          </div>
          <Badge kind="accent">ZERO-TRUST ARCHITECTURE</Badge>
        </div>

        {/* 2-Column Interactive Architecture Visualizer */}
        <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: 16, alignItems: 'start' }}>
          {/* Left Column: Visual Pipeline Steps */}
          <div className="card" style={{ padding: 14 }}>
            <div className="card-title" style={{ marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
              <ShieldIcon size={14} />
              <span>Pipeline Stages (Click to Inspect)</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {STEPS.map((s, i) => {
                const isSel = sel === s.id
                return (
                  <div key={s.id} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div
                      onClick={() => setSel(s.id)}
                      role="button"
                      tabIndex="0"
                      onKeyDown={e => { if (e.key === 'Enter') setSel(s.id) }}
                      style={{
                        padding: '10px 12px',
                        borderRadius: 4,
                        border: '1.5px solid var(--border-strong)',
                        background: isSel ? 'var(--ink)' : 'var(--surface)',
                        color: isSel ? '#ffffff' : 'var(--ink)',
                        boxShadow: isSel ? 'var(--brutal-shadow)' : 'var(--brutal-shadow-sm)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 10,
                        transition: 'transform 0.08s ease, box-shadow 0.08s ease',
                        transform: isSel ? 'translate(-1px, -1px)' : 'none',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 10,
                          fontWeight: 800,
                          padding: '2px 5px',
                          borderRadius: 3,
                          background: isSel ? 'rgba(255, 255, 255, 0.2)' : 'var(--surface-alt)',
                          border: '1px solid var(--border-strong)',
                          color: isSel ? '#ffffff' : 'var(--ink)'
                        }}>
                          {s.num}
                        </span>
                        <div>
                          <div style={{ fontWeight: 800, fontSize: 12.5, lineHeight: 1.2 }}>{s.title}</div>
                          <div style={{ fontSize: 10.5, opacity: isSel ? 0.85 : 0.6, marginTop: 2 }}>{s.sub}</div>
                        </div>
                      </div>
                      <Badge kind={isSel ? 'default' : s.badge}>{s.tag}</Badge>
                    </div>
                    {i < STEPS.length - 1 && (
                      <div style={{ textAlign: 'center', fontSize: 12, fontWeight: 800, color: 'var(--faint)', lineHeight: 1 }}>
                        ↓
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Right Column: Deep-Dive Stage Inspector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1.5px solid var(--border-strong)', paddingBottom: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 800, padding: '2px 8px', background: 'var(--ink)', color: '#ffffff', borderRadius: 4 }}>
                    STAGE {curStep.num}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 15, fontWeight: 800, textTransform: 'uppercase' }}>
                    {curStep.title}
                  </span>
                </div>
                <Badge kind={curStep.badge}>{curStep.tag}</Badge>
              </div>

              <div style={{ marginTop: 10 }}>
                <div className="section-label">Overview</div>
                <p style={{ fontSize: 13.5, color: 'var(--ink)', fontWeight: 600, lineHeight: 1.5 }}>
                  {cur.overview}
                </p>
              </div>

              <div>
                <div className="section-label">Detailed Mechanics</div>
                <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6 }}>
                  {cur.details}
                </p>
              </div>

              <div style={{ background: 'var(--accent-bg)', border: '1.5px solid var(--border-strong)', borderRadius: 4, padding: 12, boxShadow: 'var(--brutal-shadow-sm)' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 800, color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 4 }}>
                  🔒 Security Invariant Enforced
                </div>
                <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--ink)' }}>
                  {cur.invariant}
                </div>
              </div>

              <div>
                <div className="section-label">Data Signature / Code Representation</div>
                <pre className="code-block" style={{ margin: 0, fontSize: 11.5 }}>{cur.sample}</pre>
              </div>
            </div>

            {/* Architectural Zero-Trust Pillars */}
            <div className="card">
              <div className="card-title">Why This Is Mathematically Zero-Trust</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, marginTop: 4 }}>
                <div style={{ padding: 10, background: 'var(--surface-alt)', border: '1px solid var(--border-strong)', borderRadius: 4 }}>
                  <div style={{ fontWeight: 800, fontSize: 12 }}>1. Model Never Controls Memory</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>Downstream models have zero direct read, write, or revoke permissions.</div>
                </div>
                <div style={{ padding: 10, background: 'var(--surface-alt)', border: '1px solid var(--border-strong)', borderRadius: 4 }}>
                  <div style={{ fontWeight: 800, fontSize: 12 }}>2. Write-Time Defense</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>Sensitive data detection and poisoning defense scan before storage.</div>
                </div>
                <div style={{ padding: 10, background: 'var(--surface-alt)', border: '1px solid var(--border-strong)', borderRadius: 4 }}>
                  <div style={{ fontWeight: 800, fontSize: 12 }}>3. Retrieval-Time Passport</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>Consent, destination, TTL, and revocation state re-evaluated on every read.</div>
                </div>
                <div style={{ padding: 10, background: 'var(--surface-alt)', border: '1px solid var(--border-strong)', borderRadius: 4 }}>
                  <div style={{ fontWeight: 800, fontSize: 12 }}>4. Tamper-Evident Receipts</div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>Every gateway decision is SHA-256 hashed and verifiable against genesis.</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
