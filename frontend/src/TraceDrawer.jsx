// MEMVERSE Trace drawer — the judge-facing window into every request.
// Renders the REAL backend trace (12 stages) with 4 tabs:
//   Pipeline | Payload & Boundary | Receipt | Audit timeline
import React, { useEffect, useRef, useState } from 'react'
import { api, fmtMs, fmtTime, shortId, hashShort } from './api'
import { Badge, DecisionBadge, SensBadge, StageStatusIcon, Kv, SectionLabel, ShieldIcon } from './ui'

const STAGE_TITLES = {
  request: 'Request Received', memory: 'Memory Retrieval', detect: 'Sensitive Data Detection',
  defend: 'Poisoning Defense', policy: 'Policy Evaluation', transform: 'Transformation',
  passport: 'Model Passport', context: 'Approved Context', llm_gate: 'Security Boundary Check',
  llm: 'External Model', response: 'Response', receipt: 'Security Receipt',
}

const TABS = [
  { id: 'pipeline', label: 'Pipeline' },
  { id: 'payload', label: 'Payload & Boundary' },
  { id: 'receipt', label: 'Security Receipt' },
  { id: 'audit', label: 'Audit Timeline' },
]

export default function TraceDrawer({ trace, receipt, modelInput, onClose }) {
  const [tab, setTab] = useState('pipeline')
  const [open, setOpen] = useState({})
  const dialogRef = useRef(null)

  // Close on Escape anywhere (keyboard a11y) + move focus into the dialog on open.
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    dialogRef.current?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  if (!trace) return null
  const s = trace.summary || {}
  const blocked = s.blocked || s.decision === 'BLOCK'
  const llmStage = trace.stages.find(st => st.id === 'llm')
  const respStage = trace.stages.find(st => st.id === 'response')
  const modelName = respStage?.output?.model || llmStage?.output?.model || '—'

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div className="drawer" ref={dialogRef} role="dialog" aria-label="MEMVERSE Trace" aria-modal="true"
           tabIndex={-1} onClick={e => e.stopPropagation()}>
        <div className="drawer-head">
          <ShieldIcon size={16} />
          <div>
            <h3>MEMVERSE Trace</h3>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>
              {trace.request_number ? `REQ-${String(trace.request_number).padStart(4, '0')}` : trace.request_id}
              {trace.session_number ? ` · SES-${String(trace.session_number).padStart(4, '0')}` : ''}
              {' · '}{fmtTime(trace.timestamp)} · {trace.operation}
            </div>
            <div style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)', opacity: 0.8 }}>
              request_id {trace.request_id}
            </div>
          </div>
          <button className="drawer-close" onClick={onClose} aria-label="Close trace">×</button>
        </div>

        {/* header summary */}
        <div className="trace-header">
          <div className="th-cell">
            <div className="th-k">Status</div>
            <Badge kind={blocked ? 'blocked' : s.status === 'TRANSFORMED' ? 'accent' : 'ok'}>
              {blocked ? 'BLOCKED' : `✓ ${s.status || 'PROTECTED'}`}
            </Badge>
          </div>
          <div className="th-cell"><div className="th-k">Decision</div><DecisionBadge decision={s.decision} /></div>
          <div className="th-cell"><div className="th-k">Policy</div><span className="mono">{s.policy}</span></div>
          <div className="th-cell"><div className="th-k">Processing</div>
            <span className="mono">{trace.total_ms != null ? fmtMs(trace.total_ms) : '—'}</span>
          </div>
          <div className="th-cell"><div className="th-k">Model</div><span className="mono">{modelName || '—'}</span></div>
          <div className="th-cell"><div className="th-k">Gateway</div><Badge kind="ok">ONLINE</Badge></div>
        </div>

        {/* tabs */}
        <div className="trace-tabs" role="tablist">
          {TABS.map(t => (
            <button key={t.id} role="tab" aria-selected={tab === t.id}
              className={`trace-tab ${tab === t.id ? 'active' : ''}`}
              onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>

        <div className="drawer-body">
          {tab === 'pipeline' && <PipelineTab trace={trace} receipt={receipt} open={open} setOpen={setOpen} />}
          {tab === 'payload' && <PayloadTab trace={trace} modelInput={modelInput} />}
          {tab === 'receipt' && <div className="card"><div className="card-title">SECURITY RECEIPT</div><ReceiptBlock receipt={receipt} trace={trace} /></div>}
          {tab === 'audit' && <AuditTab trace={trace} />}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------- pipeline */
function PipelineTab({ trace, receipt, open, setOpen }) {
  const s = trace.summary || {}
  const boundaryIdx = trace.stages.findIndex(st => st.id === 'llm_gate')
  return (
    <>
      <div className="card" style={{ borderColor: s.blocked ? '#f3cfcf' : '#c8ece7' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
          {s.blocked
            ? <Badge kind="blocked">MEMVERSE BLOCKED — model not contacted</Badge>
            : <Badge kind="accent">✓ MEMVERSE PROTECTED</Badge>}
          {s.egress === 'CLEAN' && <Badge kind="ok">Egress CLEAN ✓</Badge>}
          {s.egress === 'FAIL' && <Badge kind="blocked">Egress FAIL</Badge>}
          {s.egress === 'BLOCKED' && <Badge kind="blocked">Egress BLOCKED</Badge>}
        </div>
        <div className="kv">
          <div className="k">Memory fields retrieved</div><div className="v">{s.fields_detected ?? 0}</div>
          <div className="k">Memory fields transformed</div><div className="v">{s.fields_transformed ?? 0}</div>
          <div className="k">Memory fields blocked</div><div className="v">{s.fields_blocked ?? 0}</div>
          <div className="k">Poisoning risk</div>
          <div className="v"><SensBadge level={s.poisoning_risk} /> {s.poisoning_risk || 'LOW'} {s.poisoning_score != null && `(score ${s.poisoning_score}/100)`}</div>
          <div className="k">Destination</div><div className="v">{s.destination}</div>
          <div className="k">Receipt</div><div className="v mono">{receipt ? shortId(receipt.event_id) : s.receipt}</div>
        </div>
      </div>

      {trace.stages.map((st, i) => (
        <React.Fragment key={st.id}>
          {i === boundaryIdx && <SecurityBoundary />}
          <Stage idx={i + 1} stage={st} open={!!open[st.id]}
            onToggle={() => setOpen(o => ({ ...o, [st.id]: !o[st.id] }))} />
        </React.Fragment>
      ))}
    </>
  )
}

function SecurityBoundary() {
  return (
    <div className="boundary" role="img" aria-label="Security boundary — trusted zone above, external model below">
      <div className="boundary-line"><span>SECURITY BOUNDARY — only approved context crosses</span></div>
      <div className="boundary-sub">⬇ EXTERNAL MODEL ZONE ⬇</div>
    </div>
  )
}

function Stage({ idx, stage, open, onToggle }) {
  return (
    <div className="stage" style={open ? { borderColor: 'var(--border-2)' } : undefined}>
      <button className="stage-head" onClick={onToggle} aria-expanded={open}
        aria-label={`${STAGE_TITLES[stage.id] || stage.name} stage`}>
        <span className="stage-num">{String(idx).padStart(2, '0')}</span>
        <StageStatusIcon status={stage.status} />
        <span className="stage-title">{STAGE_TITLES[stage.id] || stage.name}</span>
        {stage.ms > 0 && <span className="stage-ms">{fmtMs(stage.ms)}</span>}
        {stage.decision && <DecisionBadge decision={stage.decision} />}
        <span className="stage-chevron" style={{ transform: open ? 'rotate(90deg)' : 'none' }}>▶</span>
      </button>
      {open && (
        <div className="stage-body">
          {stage.ts && <div className="stage-ts">⏱ {fmtTime(stage.ts)} · {fmtMs(stage.ms)}</div>}
          {stage.explanation && <p className="explain">{stage.explanation}</p>}
          <StageContent stage={stage} />
        </div>
      )}
    </div>
  )
}

function StageContent({ stage }) {
  const out = stage.output || {}
  switch (stage.id) {
    case 'request':
      return (
        <>
          <SectionLabel>Request metadata</SectionLabel>
          <Kv rows={[
            { k: 'Request ID', v: stage.input?.request_id, mono: true },
            { k: 'Conversation ID', v: stage.input?.conversation_id, mono: true },
            { k: 'Timestamp', v: fmtTime(stage.input?.timestamp) },
            { k: 'Operation', v: <Badge kind="accent">{stage.input?.operation}</Badge> },
            { k: 'Purpose', v: stage.input?.purpose },
            { k: 'Destination', v: stage.input?.destination },
            { k: 'Input length', v: stage.input?.input_length != null ? `${stage.input.input_length} chars` : '—' },
          ]} />
          <SectionLabel>RAW USER INPUT</SectionLabel>
          <pre className="code-block">{stage.input?.prompt || '—'}</pre>
          <p style={{ fontSize: 11.5, color: 'var(--muted)', margin: '6px 0 0' }}>
            The external model did NOT receive this request directly — everything below happened first.
          </p>
        </>
      )
    case 'memory':
      return <MemoryContent out={out} />
    case 'detect':
      return <DetectionContent entities={out.entities} />
    case 'defend':
      return <DefendContent out={out} />
    case 'policy':
      return <PolicyContent out={out} />
    case 'passport':
      return <PassportContent stage={stage} out={out} />
    case 'transform':
      return <TransformContent out={out} />
    case 'context':
      return <ContextContent stage={stage} out={out} />
    case 'llm_gate':
      return <EgressContent out={out} />
    case 'llm':
      return <ModelRequestViewer out={out} />
    case 'response':
      return (
        <>
          <Kv rows={[
            { k: 'Provider', v: out.provider || '—' },
            { k: 'Model', v: out.model || '—' },
            { k: 'Latency', v: out.latency_ms ? fmtMs(out.latency_ms) : '—' },
            { k: 'Demo mode', v: out.demo ? 'yes (clearly labelled)' : 'no' },
          ]} />
          {out.text && (<>
            <SectionLabel>MODEL OUTPUT</SectionLabel>
            <pre className="code-block" style={{ color: '#d3e3f7' }}>{out.text}</pre>
          </>)}
        </>
      )
    case 'receipt':
      return <ReceiptInline out={out} />
    default:
      return <Kv rows={[{ k: 'Decision', v: stage.decision }, { k: 'Output', v: JSON.stringify(out, null, 2) }]} />
  }
}

/* ------------------------------------------------------------ components */
function MemoryContent({ out }) {
  const eligible = out.eligible || []
  const denied = out.denied || []
  if (!eligible.length && !denied.length) {
    return <p style={{ margin: 0 }}>No memories exist yet — only the (transformed) user prompt will reach the model.</p>
  }
  return (
    <>
      <SectionLabel>Eligible memories ({eligible.length}) — passport validated</SectionLabel>
      {eligible.map((m, i) => (
        <div key={i} className="memory-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontSize: 12 }}>{m.memory_id}</span>
            <Badge kind="ok">{m.passport_state}</Badge>
            <SensBadge level={m.sensitivity} />
            <Badge kind="info">{m.purpose}</Badge>
          </div>
          <div style={{ fontSize: 11.5, color: 'var(--muted)', marginTop: 5 }}>
            created {fmtTime(m.created_at)} · last access {fmtTime(m.last_access)} · TTL {m.ttl_days}d · scope: profile
          </div>
          <div style={{ marginTop: 6, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {m.fields.map((f, j) => (
              <span key={j} className="entity-chip" style={{ margin: 0 }}>
                {f.field} <span className="val">{f.value}</span> <SensBadge level={f.sensitivity} />
              </span>
            ))}
          </div>
        </div>
      ))}
      {denied.length > 0 && (
        <>
          <SectionLabel>Denied at passport validation ({denied.length}) — fail closed</SectionLabel>
          {denied.map((d, i) => (
            <div key={i} style={{ fontSize: 12, marginBottom: 4 }}>
              <span className="mono">{d.memory_id}</span> · <Badge kind="blocked">{d.status}</Badge> · {d.reason}
            </div>
          ))}
        </>
      )}
      <p style={{ fontSize: 11.5, color: 'var(--muted)', marginTop: 8 }}>
        MEMVERSE determines which memories are relevant and valid before any external model access.
      </p>
    </>
  )
}

function DetectionContent({ entities }) {
  const ents = entities || []
  if (!ents.length) {
    return <p style={{ margin: 0 }}>No sensitive fields detected in this input.</p>
  }
  return (
    <>
      <SectionLabel>Sensitive attributes detected ({ents.length})</SectionLabel>
      {ents.map((e, i) => (
        <div className="entity-chip" key={i}>
          <b>{e.entity}</b>
          <span className="val">{e.value}</span>
          <SensBadge level={e.sensitivity} />
          <span style={{ color: 'var(--faint)', fontSize: 11 }}>{(e.confidence * 100).toFixed(0)}%</span>
        </div>
      ))}
      <SectionLabel>Why these matter</SectionLabel>
      <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--ink-2)', fontSize: 12 }}>
        {ents.slice(0, 6).map((e, i) => <li key={i}><b>{e.entity}</b> — {e.reason}</li>)}
      </ul>
    </>
  )
}

function DefendContent({ out }) {
  const level = out.risk_level || 'LOW'
  const color = level === 'LOW' ? '#15803d' : level === 'MEDIUM' ? '#b45309' : '#b91c1c'
  const matches = out.matched_patterns || []
  return (
    <>
      <Kv rows={[
        { k: 'Risk score', v: `${out.risk_score ?? 0} / 100` },
        { k: 'Risk level', v: <SensBadge level={level} /> },
        { k: 'Detector action', v: <DecisionBadge decision={out.action} /> },
        { k: 'Reason', v: out.reason },
      ]} />
      <div className="riskbar" style={{ marginTop: 10 }} role="img" aria-label={`Risk score ${out.risk_score} of 100`}>
        <div style={{ width: `${Math.min(100, out.risk_score || 0)}%`, background: color }} />
      </div>
      {matches.length > 0 && (<>
        <SectionLabel>Matched patterns ({matches.length})</SectionLabel>
        <table className="tbl">
          <thead><tr><th>Pattern</th><th>Weight</th><th>Matched text</th></tr></thead>
          <tbody>
            {matches.map((m, i) => (
              <tr key={i}>
                <td>{m.pattern}</td>
                <td className="mono">{m.weight}</td>
                <td className="mono">{m.matched_text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </>)}
    </>
  )
}

function PolicyContent({ out }) {
  const rules = out.matched_rules || []
  const fields = out.per_field || []
  return (
    <>
      <div className="decision-banner" style={{
        borderColor: out.decision === 'ALLOW' ? '#cdeede' : out.decision === 'TRANSFORM' ? '#c8ece7' : '#f3cfcf',
        background: out.decision === 'ALLOW' ? 'var(--green-bg)' : out.decision === 'TRANSFORM' ? 'var(--accent-softer)' : 'var(--red-bg)',
      }}>
        <div style={{ fontSize: 20 }}>{out.decision === 'BLOCK' ? '✕' : out.decision === 'QUARANTINE' ? 'Q' : out.decision === 'TRANSFORM' ? 'T' : '✓'}</div>
        <div>
          <div className="db-title">POLICY DECISION: {out.decision}</div>
          <div style={{ fontSize: 12, marginTop: 3 }}>{out.reason}</div>
        </div>
      </div>
      <div className="kv" style={{ marginBottom: 8 }}>
        <div className="k">Policy version</div><div className="v mono">v1.4</div>
        <div className="k">Evaluation mode</div><div className="v">deterministic rule engine</div>
      </div>
      {rules.length > 0 && (<>
        <SectionLabel>Matched policy rules</SectionLabel>
        {rules.map((r, i) => (
          <div key={i} style={{ fontSize: 12, marginBottom: 4, color: 'var(--ink-2)' }}>
            <code style={{ background: '#eef2f7', padding: '1px 6px', borderRadius: 4 }}>{r.rule_id}</code>
            {' → '}{r.then} · {r.reason}
          </div>
        ))}
      </>)}
      {fields.length > 0 && (<>
        <SectionLabel>Per-field strategy ({fields.length})</SectionLabel>
        <table className="tbl">
          <thead><tr><th>Field</th><th>Raw value</th><th>Policy</th><th>Reason</th></tr></thead>
          <tbody>
            {fields.map((f, i) => (
              <tr key={i}>
                <td><b>{f.field}</b> <SensBadge level={f.sensitivity} /></td>
                <td className="mono">{f.raw_value || '—'}</td>
                <td><DecisionBadge decision={f.action} /></td>
                <td style={{ fontSize: 11.5, color: 'var(--muted)' }}>{f.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </>)}
    </>
  )
}

function PassportContent({ stage, out }) {
  const denied = out.denied || []
  if (out.passport === null || out.passport === undefined || out.passport === 'None') {
    return (
      <div className="decision-banner" style={{ borderColor: out.reason && String(out.reason).includes('no memory') ? '#e5e9f0' : '#f3cfcf', background: out.reason && String(out.reason).includes('no memory') ? 'var(--surface)' : 'var(--red-bg)' }}>
        <div style={{ fontSize: 20 }}>🪪</div>
        <div>
          <div className="db-title">{out.reason && String(out.reason).includes('no memory') ? 'NO PASSPORT INVOLVED' : 'NO PASSPORT ISSUED'}</div>
          <div style={{ fontSize: 12, marginTop: 3 }}>{out.reason || stage.explanation}</div>
        </div>
      </div>
    )
  }
  if (out.eligible && out.eligible.length === 0 && denied.length > 0) {
    return (
      <>
        <div className="decision-banner" style={{ borderColor: '#f3cfcf', background: 'var(--red-bg)' }}>
          <div style={{ fontSize: 20 }}>✕</div>
          <div>
            <div className="db-title">RETRIEVAL DENIED — FAIL CLOSED</div>
            <div style={{ fontSize: 12, marginTop: 3 }}>
              No memory was eligible. Denied records below never reached the model.
            </div>
          </div>
        </div>
        <SectionLabel>Denied at passport validation</SectionLabel>
        {denied.map((d, i) => (
          <div key={i} style={{ fontSize: 12, marginBottom: 4 }}>
            <span className="mono">{d.memory_id}</span> · <Badge kind="blocked">{d.status}</Badge> · {d.reason}
          </div>
        ))}
      </>
    )
  }
  const p = out.passport
  if (!p) return <p style={{ margin: 0 }}>Passport validation output: {JSON.stringify(out)}</p>
  const revoked = ['REVOKED', 'QUARANTINED', 'EXPIRED'].includes(p.revocation_state)
  return (
    <>
      <div className="passport-card">
        <div className="passport-head">
          <span>MEMORY PASSPORT</span>
          <span>{p.revocation_state}</span>
        </div>
        <div className="passport-body">
          <div><div className="k">Memory</div><div className="v">{p.memory_id}</div></div>
          <div><div className="k">Sensitivity</div><div className="v"><SensBadge level={p.sensitivity} /> {p.sensitivity}</div></div>
          <div><div className="k">Purpose</div><div className="v">{p.purpose}</div></div>
          <div><div className="k">Consent</div><div className="v">{p.consent}</div></div>
          <div><div className="k">Destination</div><div className="v">{p.destination}</div></div>
          <div><div className="k">TTL</div><div className="v">{p.ttl_days} days</div></div>
          <div><div className="k">Created</div><div className="v">{fmtTime(p.created_at)}</div></div>
          <div><div className="k">Expires</div><div className="v">{fmtTime(p.expires_at)}</div></div>
          <div><div className="k">Policy</div><div className="v">{p.policy_version}</div></div>
          <div><div className="k">Revocation</div><div className="v">{p.revocation_state}</div></div>
          <div style={{ gridColumn: '1 / -1' }}>
            <div className="k">Integrity (SHA-256)</div>
            <div className="v">{hashShort(p.integrity_hash)}</div>
          </div>
        </div>
      </div>
      <p style={{ fontSize: 11.5, color: 'var(--muted)', marginTop: 8 }}>
        This passport represents the subset/context the external model is authorized to receive.
        {revoked && <span style={{ color: 'var(--red)' }}> It is not eligible for retrieval — the gateway fails closed.</span>}
      </p>
    </>
  )
}

function TransformContent({ out }) {
  const entries = out.approved_entries || []
  const excluded = out.excluded_raw || []
  if (!entries.length) {
    return <p style={{ margin: 0 }}>No fields were released. Nothing was transformed.</p>
  }
  return (
    <>
      <div className="raw-vs-approved" style={{ marginBottom: 12 }}>
        <div className="panel-box">
          <div className="ph raw">BEFORE — raw context</div>
          <pre>{(out.per_field || []).map(f => `${f.field}: ${f.raw_value}`).join('\n') || '—'}</pre>
        </div>
        <div className="panel-box">
          <div className="ph approved">AFTER — approved representation</div>
          <pre>{entries.map(e => `${e.field}: ${e.value}`).join('\n')}</pre>
        </div>
      </div>
      <SectionLabel>Field-level transformation — FIELD · RAW · POLICY · OUTPUT</SectionLabel>
      <table className="tbl">
        <thead><tr><th>Field</th><th>Raw value</th><th>Policy</th><th>Output (model)</th></tr></thead>
        <tbody>
          {entries.map((e, i) => {
            const field = (out.per_field || []).find(f => f.field === e.field) || {}
            return (
              <tr key={i}>
                <td><b>{e.field}</b> <SensBadge level={e.sensitivity} /></td>
                <td className="mono" style={{ color: 'var(--red)', textDecoration: 'line-through', textDecorationColor: '#f3cfcf' }}>
                  {field.raw_value || '—'}
                </td>
                <td><DecisionBadge decision={field.action} /></td>
                <td className="mono" style={{ color: 'var(--green)' }}>{e.value}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {excluded.length > 0 && (
        <>
          <SectionLabel>Withheld from the model — raw values never crossed the boundary</SectionLabel>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {excluded.map((v, i) => (
              <span key={i} className="mono" style={{ fontSize: 11, background: 'var(--red-bg)', color: 'var(--red)', padding: '3px 8px', borderRadius: 6 }}>
                {v}
              </span>
            ))}
          </div>
        </>
      )}
    </>
  )
}

function ContextContent({ stage, out }) {
  const rawMem = stage.input?.raw_memory || []
  const denied = stage.input?.denied || []
  return (
    <>
      <div className="raw-vs-approved">
        <div className="panel-box">
          <div className="ph raw">RAW MEMORY (never sent)</div>
          {rawMem.length ? <pre>{rawMem.map(m => `${m.field}: ${m.value} [${m.sensitivity}]`).join('\n')}</pre> : <pre>— no raw memory context —</pre>}
        </div>
        <div className="panel-box">
          <div className="ph approved">APPROVED CONTEXT SENT TO MODEL</div>
          <pre>{out.assembly || '(empty — nothing approved)'}</pre>
        </div>
      </div>
      {denied.length > 0 && (
        <>
          <SectionLabel>Denied candidates</SectionLabel>
          {denied.map((d, i) => (
            <div key={i} style={{ fontSize: 12, marginBottom: 3 }}>
              <span className="mono">{d.memory_id}</span> — {d.reason}
            </div>
          ))}
        </>
      )}
      {out.sanitized_prompt && (
        <>
          <SectionLabel>Sanitized user prompt (sensitive values replaced)</SectionLabel>
          <pre className="code-block">{out.sanitized_prompt}</pre>
        </>
      )}
    </>
  )
}

function EgressContent({ out }) {
  const checks = out.checks || []
  return (
    <>
      <Kv rows={[
        { k: 'Egress status', v: <Badge kind={out.status === 'PASS' ? 'ok' : 'blocked'}>{out.status === 'PASS' ? 'PASS' : out.status}</Badge> },
        { k: 'Prohibited fields', v: out.prohibited_fields ?? 0 },
      ]} />
      {out.status !== 'PASS' && out.status !== 'NOT REACHED' && (
        <p style={{ color: 'var(--red)', fontSize: 12, margin: '8px 0 0' }}>
          Prohibited content detected — the model request was BLOCKED at the final boundary.
        </p>
      )}
      {checks.length > 0 && (
        <>
          <SectionLabel>Validation checks</SectionLabel>
          <table className="tbl">
            <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>
              {checks.map((c, i) => (
                <tr key={i}>
                  <td>{c.name}</td>
                  <td><Badge kind={c.status === 'PASS' ? 'ok' : 'blocked'}>{c.status}</Badge></td>
                  <td style={{ fontSize: 11.5, color: 'var(--muted)' }}>{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  )
}

/* hard evidence: was the external model contacted? */
function ModelRequestViewer({ out }) {
  const status = out.status || '—'
  const kind = status === 'SENT' ? 'ok' : status === 'NOT SENT' ? 'blocked' : status === 'FAILED' ? 'blocked' : 'info'
  return (
    <>
      <div className="decision-banner" style={{
        borderColor: status === 'SENT' ? '#cdeede' : '#f3cfcf',
        background: status === 'SENT' ? 'var(--green-bg)' : 'var(--red-bg)',
      }}>
        <div style={{ fontSize: 20 }}>{status === 'SENT' ? '↑' : status === 'FAILED' ? '⚠' : '✕'}</div>
        <div>
          <div className="db-title">EXTERNAL MODEL REQUEST — {status}</div>
          <div style={{ fontSize: 12, marginTop: 3 }}>
            {status === 'SENT' && 'The approved payload crossed the security boundary to NVIDIA.'}
            {status === 'NOT SENT' && `The model was never contacted. ${out.reason || 'Policy blocked the request.'}`}
            {status === 'FAILED' && `The model was unreachable. ${out.error || ''} No raw memory was exposed.`}
          </div>
        </div>
      </div>
      <Kv rows={[
        { k: 'Status', v: <Badge kind={kind}>{status}</Badge> },
        { k: 'Destination', v: out.destination || '—' },
        { k: 'Request ID', v: out.request_id || '—', mono: true },
        { k: 'Timestamp', v: fmtTime(out.timestamp) },
        { k: 'Provider', v: out.provider || '—' },
        { k: 'Model', v: out.model || '—' },
        { k: 'Payload hash', v: out.payload_hash ? hashShort(out.payload_hash) : '—', mono: true },
      ]} />
      {out.payload && (
        <>
          <SectionLabel>Payload as sent</SectionLabel>
          <pre className="code-block">{JSON.stringify(out.payload, null, 2)}</pre>
        </>
      )}
    </>
  )
}

function ReceiptInline({ out }) {
  return (
    <Kv rows={[
      { k: 'Receipt ID', v: out.receipt_id, mono: true },
      { k: 'Event hash', v: out.event_hash ? hashShort(out.event_hash) : '—', mono: true },
      { k: 'Previous hash', v: out.previous_event_hash ? hashShort(out.previous_event_hash) : '—', mono: true },
    ]} />
  )
}

/* ------------------------------------------------------- payload & boundary */
function PayloadTab({ trace, modelInput }) {
  const [showJson, setShowJson] = useState(false)
  const ctxStage = trace.stages.find(s => s.id === 'context')
  const llmStage = trace.stages.find(s => s.id === 'llm')
  const respStage = trace.stages.find(s => s.id === 'response')
  const trStage = trace.stages.find(s => s.id === 'transform')

  // approved context: prefer the actual modelInput messages, fall back to trace data
  let systemContent = modelInput?.messages?.find(m => m.role === 'system')?.content || ''
  let userContent = modelInput?.messages?.find(m => m.role === 'user')?.content || ctxStage?.output?.sanitized_prompt || trace.prompt
  let approved = ''
  const idx = systemContent.indexOf('APPROVED MEMORY CONTEXT:')
  if (idx >= 0) approved = systemContent.slice(idx + 'APPROVED MEMORY CONTEXT:'.length).trim()
  if (!approved) approved = (trStage?.output?.approved_entries || []).map(e => `${e.field}: ${e.value}`).join('\n')
  if (!approved) approved = ctxStage?.output?.assembly || '(empty — nothing was approved)'
  const excluded = trStage?.output?.excluded_raw || []
  const llmOut = llmStage?.output || {}
  const respOut = respStage?.output || {}

  return (
    <>
      <div className="card" style={{ borderColor: '#c8ece7' }}>
        <div className="card-title">🔎 USER ASKED</div>
        <pre className="code-block" style={{ marginTop: 8 }}>{trace.prompt}</pre>
      </div>

      <div className="flow-arrow">↓ MEMVERSE · detection · policy · transformation ↓</div>

      <div className="boundary" role="img" aria-label="Security boundary">
        <div className="boundary-line"><span>SECURITY BOUNDARY — only approved context crosses</span></div>
      </div>

      <div className="card" style={{ borderColor: '#cdeede', background: 'var(--green-bg)' }}>
        <div className="card-title">WHAT NVIDIA RECEIVED</div>
        <div className="panel-box" style={{ marginTop: 8 }}>
          <div className="ph approved">APPROVED MEMORY CONTEXT (system prompt)</div>
          <pre>{approved}</pre>
        </div>
        {userContent && userContent !== trace.prompt && (
          <div className="panel-box" style={{ marginTop: 10 }}>
            <div className="ph approved">USER MESSAGE AS DELIVERED (sanitized)</div>
            <pre>{userContent}</pre>
          </div>
        )}
        {userContent === trace.prompt && (
          <p style={{ fontSize: 11.5, color: 'var(--muted)', margin: '8px 0 0' }}>
            The user message contained no sensitive values, so it was forwarded unchanged.
          </p>
        )}
        {excluded.length > 0 && (
          <>
            <SectionLabel>Raw sensitive memory was NOT transmitted</SectionLabel>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {excluded.map((v, i) => (
                <span key={i} className="mono" style={{ fontSize: 11, background: 'var(--red-bg)', color: 'var(--red)', padding: '3px 8px', borderRadius: 6 }}>
                  {v}
                </span>
              ))}
            </div>
          </>
        )}
      </div>

      {/* hard evidence of the model call */}
      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">External model request</div>
        <Kv rows={[
          { k: 'Status', v: <Badge kind={llmOut.status === 'SENT' ? 'ok' : llmOut.status === 'NOT SENT' ? 'blocked' : 'blocked'}>{llmOut.status || '—'}</Badge> },
          { k: 'Destination', v: llmOut.destination || '—' },
          { k: 'Request ID', v: llmOut.request_id || '—', mono: true },
          { k: 'Timestamp', v: fmtTime(llmOut.timestamp) },
          { k: 'Payload hash', v: llmOut.payload_hash ? hashShort(llmOut.payload_hash) : '—', mono: true },
        ]} />
        {llmOut.status === 'NOT SENT' && llmOut.reason && (
          <p style={{ fontSize: 12, color: 'var(--red)', margin: '8px 0 0' }}>Reason: {llmOut.reason}</p>
        )}
        {llmOut.status === 'FAILED' && llmOut.error && (
          <p style={{ fontSize: 12, color: 'var(--amber)', margin: '8px 0 0' }}>⚠ {llmOut.error}</p>
        )}
        <button className="btn btn-sm" style={{ marginTop: 10 }} onClick={() => setShowJson(!showJson)} aria-expanded={showJson}>
          {showJson ? 'Hide' : 'Show'} exact payload JSON
        </button>
        {showJson && <pre className="code-block" style={{ marginTop: 10 }}>{JSON.stringify(modelInput || llmOut.payload || {}, null, 2)}</pre>}
      </div>

      <div className="card">
        <div className="card-title">MODEL RESPONSE</div>
        <pre className="code-block" style={{ marginTop: 8, color: '#d3e3f7' }}>{respOut.text || '—'}</pre>
        <p style={{ fontSize: 11.5, color: 'var(--muted)', margin: '8px 0 0' }}>
          {respOut.demo ? 'Generated by the clearly-labelled DEMO provider (no NVIDIA_API_KEY configured).' : `Live response from ${respOut.model || 'NVIDIA'}.`}
        </p>
      </div>
    </>
  )
}

/* -------------------------------------------------------------- receipt */
export function ReceiptBlock({ receipt, trace }) {
  const [verifying, setVerifying] = useState(false)
  const [result, setResult] = useState(null)
  if (!receipt) return <p style={{ margin: 0 }}>No receipt for this event.</p>

  const verify = async () => {
    setVerifying(true)
    try {
      const r = await api.receiptVerify(receipt.event_id)
      setResult(r)
    } catch (e) {
      setResult({ verified: false, reason: String(e) })
    } finally { setVerifying(false) }
  }

  return (
    <div>
      <div className="receipt-box">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
          <Badge kind="gold">RECEIPT</Badge>
          <span className="mono" style={{ fontSize: 12 }}>{receipt.event_id}</span>
          <Badge kind="info">{receipt.event_type}</Badge>
          <DecisionBadge decision={receipt.decision} />
          {result?.verified === true && <Badge kind="ok">INTEGRITY VERIFIED ✓</Badge>}
          {result?.verified === false && <Badge kind="blocked">VERIFICATION FAILED</Badge>}
        </div>
        <Kv rows={[
          { k: 'Request ID', v: trace?.request_id || receipt.extra?.request_id || '—', mono: true },
          { k: 'Timestamp', v: fmtTime(receipt.timestamp) },
          { k: 'Policy version', v: receipt.policy_version },
          { k: 'Decision', v: receipt.decision },
          { k: 'Purpose', v: receipt.purpose },
          { k: 'Destination', v: receipt.destination },
          { k: 'Memory fields retrieved', v: receipt.fields_detected },
          { k: 'Memory fields transformed', v: receipt.fields_transformed },
          { k: 'Passport', v: receipt.passport_id || '—', mono: true },
          { k: 'Revocation state', v: receipt.revocation_state || '—' },
        ]} />
        <SectionLabel>Hash-linked chain (SHA-256)</SectionLabel>
        <div className="hash-line">previous → {hashShort(receipt.previous_event_hash)}</div>
        <div className="hash-line">current  → {hashShort(receipt.event_hash)}</div>
        <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <button className="btn btn-sm" onClick={verify} disabled={verifying}>
            {verifying ? <span className="spin" /> : '🔍'} Verify Integrity
          </button>
          {result && (
            <span style={{ fontSize: 11.5, color: result.verified ? 'var(--green)' : 'var(--red)' }}>
              {result.verified
                ? `✓ recomputed hash matches · chain intact (${result.chain_length} link(s))`
                : `✗ ${result.reason || 'hash mismatch or broken chain'}`}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------ audit timeline */
function AuditTab({ trace }) {
  const stages = trace.stages || []
  const rows = []
  stages.forEach((s, i) => {
    rows.push({
      ts: s.ts,
      label: STAGE_TITLES[s.id] || s.name,
      status: s.status,
      ms: s.ms,
      detail: s.explanation,
      decision: s.decision,
    })
  })
  const total = trace.total_ms != null ? trace.total_ms : trace.memverse_ms
  return (
    <>
      <div className="card">
        <div className="card-title">Audit timeline — {trace.request_number ? `REQ-${String(trace.request_number).padStart(4, '0')}` : trace.request_id}</div>
        <p className="card-sub">Real timestamps recorded by the gateway for this request.</p>
        <div className="timeline">
          {rows.map((r, i) => (
            <div className="tl-row" key={i}>
              <div className="tl-time mono">{r.ts ? fmtTime(r.ts) : '—'}</div>
              <div className="tl-dot" style={{ background: r.status === 'ok' ? '#15803d' : r.status === 'blocked' ? '#b91c1c' : r.status === 'warn' ? '#b45309' : '#94a3b8' }} />
              <div className="tl-body">
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <b>{r.label}</b>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--faint)' }}>{fmtMs(r.ms)}</span>
                  {r.decision && <DecisionBadge decision={r.decision} />}
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--muted)' }}>{r.detail}</div>
              </div>
            </div>
          ))}
          <div className="tl-row">
            <div className="tl-time mono">—</div>
            <div className="tl-dot" style={{ background: 'var(--accent)' }} />
            <div className="tl-body">
              <b>Total</b>
              <span className="mono" style={{ fontSize: 11, color: 'var(--faint)', marginLeft: 8 }}>{fmtMs(total)}</span>
            </div>
          </div>
        </div>
      </div>
      <div className="card">
        <div className="card-title">Performance breakdown</div>
        <table className="tbl">
          <thead><tr><th>Segment</th><th>Time</th></tr></thead>
          <tbody>
            <tr><td>MEMVERSE processing (retrieval → egress)</td><td className="mono">{fmtMs(trace.memverse_ms)}</td></tr>
            <tr><td>External model response</td><td className="mono">{fmtMs(trace.model_ms)}</td></tr>
            <tr><td><b>Total end-to-end</b></td><td className="mono"><b>{fmtMs(total)}</b></td></tr>
          </tbody>
        </table>
        <p style={{ fontSize: 11, color: 'var(--faint)', margin: '8px 0 0' }}>
          Live measurements from this request — not fabricated benchmarks.
        </p>
      </div>
    </>
  )
}
