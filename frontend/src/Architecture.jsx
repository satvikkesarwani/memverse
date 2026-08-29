// How MEMVERSE Works — interactive architecture
import React, { useState } from 'react'

const STEPS = [
  { id: 'app', title: 'Application', sub: 'React chat UI' },
  { id: 'gateway', title: 'MEMVERSE GATEWAY', sub: 'single choke point' },
  { id: 'detect', title: 'DETECT', sub: 'sensitive-data scan' },
  { id: 'defend', title: 'DEFEND', sub: 'poisoning defense' },
  { id: 'policy', title: 'POLICY', sub: 'versioned rules engine' },
  { id: 'passport', title: 'PASSPORT', sub: 'consent · TTL · revocation' },
  { id: 'transform', title: 'TRANSFORM', sub: 'suppress · generalize · redact' },
  { id: 'egress', title: 'EGRESS', sub: 'final validation' },
  { id: 'approved', title: 'APPROVED CONTEXT', sub: 'only this reaches the model' },
  { id: 'llm', title: 'NVIDIA MODEL', sub: 'untrusted downstream consumer' },
]

const EXPLANATIONS = {
  app: 'A normal AI chatbot. Users never talk to the model directly — every prompt is submitted to the MEMVERSE gateway.',
  gateway: 'The single choke point. There is no other path to memory or to the model: writes, reads, reveals, revocation and egress all pass through here. Nothing can bypass it.',
  detect: 'Deterministic sensitive-data detection (regex + context rules): names, age, location, email, phone, health, financial data, credentials and secrets — each classified by sensitivity with confidence.',
  defend: 'Memory-poisoning / prompt-injection defense. Weighted pattern scoring assigns a risk level; HIGH/CRITICAL inputs are quarantined or blocked before they can become memory or reach the model.',
  policy: 'A versioned typed policy (currently v1.4). Rules like "passport revoked → BLOCK" and a sensitivity × operation matrix decide what may be remembered, revealed, and learned. Deterministic and reproducible.',
  passport: 'Every memory carries a Memory Passport: purpose, consent, destination, TTL/expiry, integrity hash and revocation state. Retrieval validates the passport first and fails closed on REVOKED / QUARANTINED / EXPIRED.',
  transform: 'Field-level transformation per the policy matrix: SUPPRESS identity, GENERALIZE age/location/education, REDACT contact details, TOKENIZE where appropriate. Raw values never cross the boundary.',
  egress: 'The final security boundary. The exact payload about to be sent to the model is re-scanned for prohibited fields. If anything is found, the model request is BLOCKED — never merely warned.',
  approved: 'The assembled, sanitized representation — the only thing the model ever sees. Raw memory never reaches it.',
  llm: 'The model is treated as an untrusted downstream consumer of approved context. It cannot write memory, read memory, or control policy. NVIDIA is called server-side via NVIDIA_API_KEY (never in the browser); without a key, a clearly-labelled demo provider answers.',
}

export default function Architecture() {
  const [sel, setSel] = useState('gateway')

  return (
    <div className="page">
      <div className="page-inner">
        <h2>How MEMVERSE Works</h2>
        <p className="page-sub">
          The model never receives memory directly — it receives only the representation approved by
          MEMVERSE. Click any component to understand it.
        </p>

        <div className="card">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {STEPS.map((s, i) => (
              <React.Fragment key={s.id}>
                <div
                  className={`arch-node ${sel === s.id ? 'sel' : ''}`}
                  onClick={() => setSel(s.id)}
                  role="button" tabIndex="0"
                  onKeyDown={e => { if (e.key === 'Enter') setSel(s.id) }}
                  style={{
                    borderColor: s.id === 'gateway' ? 'var(--accent)' : undefined,
                    background: s.id === 'gateway' && sel !== 'gateway' ? 'var(--accent-softer)' : undefined,
                  }}
                  aria-pressed={sel === s.id}
                >
                  <div className="an-title">{s.title}</div>
                  <div className="an-sub">{s.sub}</div>
                </div>
                {i < STEPS.length - 1 && <div className="arch-arrow">↓</div>}
              </React.Fragment>
            ))}
          </div>
        </div>

        <div className="card" style={{ borderColor: '#c8ece7', background: 'var(--accent-softer)' }}>
          <div className="card-title">{STEPS.find(s => s.id === sel)?.title}</div>
          <p style={{ fontSize: 13, color: 'var(--ink-2)', margin: '6px 0 0', lineHeight: 1.6 }}>
            {EXPLANATIONS[sel]}
          </p>
        </div>

        <div className="card">
          <div className="card-title">Why this is zero-trust</div>
          <ul style={{ fontSize: 12.5, color: 'var(--ink-2)', lineHeight: 1.7, margin: '6px 0 0', paddingLeft: 20 }}>
            <li><b>Model never directly controls memory.</b> It cannot write, read, or revoke anything.</li>
            <li><b>Write-time enforcement:</b> nothing is stored until detection, poisoning defense and policy approve an <i>encrypted, local-only</i> representation.</li>
            <li><b>Retrieval-time enforcement:</b> passport (consent · TTL · revocation) is re-validated on every read, against the current policy.</li>
            <li><b>Fail closed:</b> revoked, expired, quarantined or unvalidatable memory never reaches the model.</li>
            <li><b>Evidence:</b> every decision produces a tamper-evident, hash-linked receipt that can be re-verified.</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
