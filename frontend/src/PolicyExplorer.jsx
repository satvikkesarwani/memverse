// Policy Explorer — Live Policy-as-Code Engine + LEARN Control Surface Console
import React, { useEffect, useState } from 'react'
import { api, fmtTime, shortId, hashShort } from './api'
import { Badge, DecisionBadge } from './ui'
import { ReceiptBlock } from './TraceDrawer'

const PURPOSE_LABELS = {
  answer_query: 'Answer user query',
  personalization: 'Personalization',
  task_execution: 'Task execution',
  context: 'Assistant context',
  assistance: 'Assistance',
  chat: 'Chat assistance',
  model_finetuning: 'Model Fine-tuning / Training',
  federated_analytics: 'Federated Analytics',
  rag_index_update: 'RAG Index Update',
}

const ACTION_OPTIONS = ['ALLOW', 'TRANSFORM', 'GENERALIZE', 'SUPPRESS', 'REDACT', 'BLOCK']

export default function PolicyExplorer() {
  const [policy, setPolicy] = useState(null)
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState('')
  const [fieldStrat, setFieldStrat] = useState({})

  // LEARN Control Surface State
  const [learnPurpose, setLearnPurpose] = useState('model_finetuning')
  const [epsilon, setEpsilon] = useState(0.5)
  const [learnBusy, setLearnBusy] = useState(false)
  const [learnResult, setLearnResult] = useState(null)

  const load = async () => {
    try {
      const p = await api.policy()
      setPolicy(p)
      setFieldStrat(p.field_strategy || {})
    } catch { /* ignore */ }
  }

  useEffect(() => { load() }, [])

  const onActionChange = (type, mode, val) => {
    setFieldStrat(prev => ({
      ...prev,
      [type]: {
        ...(prev[type] || {}),
        [mode]: val,
      }
    }))
  }

  const savePolicy = async () => {
    setSaving(true)
    setSaveMsg('')
    try {
      const res = await api.policyUpdate({ field_strategy: fieldStrat })
      setPolicy(res.policy)
      setSaveMsg('✓ Policy updated & hot-reloaded across gateway.')
    } catch (e) {
      setSaveMsg(`✗ Update failed: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  const resetPolicy = async () => {
    setSaving(true)
    setSaveMsg('')
    try {
      const res = await api.policyReset()
      setPolicy(res.policy)
      setFieldStrat(res.policy.field_strategy || {})
      setSaveMsg('✓ Policy reset to default v1.4.')
    } catch (e) {
      setSaveMsg(`✗ Reset failed: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  const runLearnExport = async () => {
    setLearnBusy(true)
    setLearnResult(null)
    try {
      const r = await api.learnExport({
        purpose: learnPurpose,
        destination: 'learn_pipeline',
        privacy_budget_epsilon: parseFloat(epsilon),
      })
      setLearnResult(r)
    } catch (e) {
      setLearnResult({ error: e.message || String(e) })
    } finally {
      setLearnBusy(false)
    }
  }

  if (!policy) {
    return (
      <div className="page">
        <div className="page-inner">
          <div className="empty-note">Loading policy…</div>
        </div>
      </div>
    )
  }

  const matrix = policy.purpose_matrix || {}
  const ttl = policy.ttl_default_days || {}

  return (
    <div className="page">
      <div className="page-inner">
        <h2>Policy Explorer &amp; Governance</h2>
        <p className="page-sub">
          Decisions are governed by this versioned, typed policy-as-code contract.
          Modify field strategies live or run the <b>LEARN</b> dataset export governance pipeline.
        </p>

        {/* Policy Header */}
        <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div className="card-title" style={{ margin: 0 }}>
              MEMVERSE POLICY <Badge kind="accent">{policy.version}</Badge>
              <Badge kind="info">{policy.name}</Badge>
            </div>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
              Active on Gateway · Updated {policy.updated} · Dynamic Rule Evaluation
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-sm btn-primary" onClick={savePolicy} disabled={saving}>
              {saving ? 'Saving…' : '💾 Save & Apply Policy'}
            </button>
            <button className="btn btn-sm" onClick={resetPolicy} disabled={saving}>
              ⟲ Reset Defaults
            </button>
          </div>
        </div>

        {saveMsg && (
          <div className="card" style={{ padding: '10px 14px', background: 'var(--accent-bg)', borderColor: 'var(--accent)' }}>
            <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>{saveMsg}</span>
          </div>
        )}

        {/* Interactive Field Strategy Table */}
        <div className="card">
          <div className="card-title">Live Field-Level Strategy (Editable)</div>
          <p className="card-sub">
            Control exactly what transformation action is enforced when a field type crosses a boundary.
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 160 }}>Field Type</th>
                  <th>On TRANSFORM</th>
                  <th>On ALLOW</th>
                  <th>On BLOCK</th>
                  <th>On LEARN</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(fieldStrat).map(([type, strat]) => (
                  <tr key={type}>
                    <td><b>{type.toUpperCase()}</b></td>
                    <td>
                      <select
                        style={{ padding: '3px 6px', fontSize: 11, fontFamily: 'var(--font-mono)', border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)' }}
                        value={strat.TRANSFORM || 'GENERALIZE'}
                        onChange={e => onActionChange(type, 'TRANSFORM', e.target.value)}
                      >
                        {ACTION_OPTIONS.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                      </select>
                    </td>
                    <td>
                      <select
                        style={{ padding: '3px 6px', fontSize: 11, fontFamily: 'var(--font-mono)', border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)' }}
                        value={strat.ALLOW || 'ALLOW'}
                        onChange={e => onActionChange(type, 'ALLOW', e.target.value)}
                      >
                        {ACTION_OPTIONS.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                      </select>
                    </td>
                    <td>
                      <Badge kind="blocked">{strat.BLOCK || 'BLOCK'}</Badge>
                    </td>
                    <td>
                      <select
                        style={{ padding: '3px 6px', fontSize: 11, fontFamily: 'var(--font-mono)', border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)' }}
                        value={strat.GENERALIZE || 'GENERALIZE'}
                        onChange={e => onActionChange(type, 'GENERALIZE', e.target.value)}
                      >
                        {ACTION_OPTIONS.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* LEARN Control Surface Workbench */}
        <div className="card" style={{ borderColor: 'var(--accent)' }}>
          <div className="card-title">
            <span>LEARN Control Surface (Model Training &amp; Dataset Governance)</span>
            <Badge kind="accent">ACTIVE GOVERNANCE</Badge>
          </div>
          <p className="card-sub">
            Simulate or execute privacy-preserving dataset export for model fine-tuning or RAG index aggregation.
            MEMVERSE enforces consent filters, sensitivity exclusions, and differential privacy noise.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginBottom: 14 }}>
            <div>
              <div className="section-label">Target Learning Purpose</div>
              <select
                style={{ width: '100%', padding: '6px 8px', fontSize: 12, fontFamily: 'var(--font-mono)', border: '1.5px solid var(--border-strong)', borderRadius: 'var(--radius-sm)' }}
                value={learnPurpose}
                onChange={e => setLearnPurpose(e.target.value)}
              >
                <option value="model_finetuning">Model Fine-tuning</option>
                <option value="federated_analytics">Federated Analytics</option>
                <option value="rag_index_update">RAG Index Update</option>
              </select>
            </div>
            <div>
              <div className="section-label">Privacy Budget (ε = {epsilon})</div>
              <input
                type="range"
                min="0.1"
                max="2.0"
                step="0.1"
                value={epsilon}
                onChange={e => setEpsilon(e.target.value)}
                style={{ width: '100%' }}
              />
              <div style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                Laplace noise scale: b = {round100(1.0 / parseFloat(epsilon))}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end' }}>
              <button
                className="btn btn-primary"
                style={{ width: '100%', height: 34 }}
                onClick={runLearnExport}
                disabled={learnBusy}
              >
                {learnBusy ? 'Evaluating…' : '▶ Execute LEARN Export'}
              </button>
            </div>
          </div>

          {learnResult && (
            <div style={{ marginTop: 14 }}>
              {learnResult.error ? (
                <div style={{ color: 'var(--red)', fontSize: 12 }}>Error: {learnResult.error}</div>
              ) : (
                <>
                  <div className="kv" style={{ background: 'var(--surface-alt)', padding: 12, border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                    <div className="k">Candidates Evaluated</div><div className="v mono">{learnResult.total_candidates} records</div>
                    <div className="k">Approved for Export</div><div className="v mono" style={{ color: 'var(--green)', fontWeight: 700 }}>{learnResult.eligible_count} records</div>
                    <div className="k">Excluded (Protected)</div><div className="v mono" style={{ color: 'var(--red)', fontWeight: 700 }}>{learnResult.excluded_count} records</div>
                    <div className="k">Privacy Budget (ε)</div><div className="v mono">{learnResult.privacy_budget_epsilon}</div>
                  </div>

                  {learnResult.excluded_records?.length > 0 && (
                    <div style={{ marginTop: 10 }}>
                      <div className="section-label">Excluded Records &amp; Policy Rationales</div>
                      <table className="tbl">
                        <thead><tr><th>Memory ID</th><th>Sensitivity</th><th>Exclusion Rationale</th></tr></thead>
                        <tbody>
                          {learnResult.excluded_records.map((ex, i) => (
                            <tr key={i}>
                              <td className="mono">{ex.memory_id}</td>
                              <td><Badge kind="blocked">{ex.sensitivity}</Badge></td>
                              <td style={{ fontSize: 11.5, color: 'var(--red)' }}>{ex.reason}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {learnResult.receipt && (
                    <div style={{ marginTop: 12 }}>
                      <ReceiptBlock receipt={learnResult.receipt} />
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        {/* Policy Rules */}
        <div className="card">
          <div className="card-title">Precondition Rules (Evaluated in Priority Order)</div>
          <table className="tbl">
            <thead>
              <tr><th>Rule ID</th><th>Precondition</th><th>Enforced Action</th><th>Rationale</th></tr>
            </thead>
            <tbody>
              {(policy.rules || []).map(r => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td><code>IF</code> {Object.entries(r.if).map(([k, v]) => `${k} = ${JSON.stringify(v)}`).join(' AND ')}</td>
                  <td><DecisionBadge decision={r.then} /></td>
                  <td style={{ fontSize: 11.5, color: 'var(--muted)' }}>{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Purpose Matrix */}
        <div className="card">
          <div className="card-title">Sensitivity × Surface Matrix (Remember / Reveal / Learn)</div>
          <table className="tbl">
            <thead>
              <tr><th>Sensitivity</th><th>REVEAL (Read → Model)</th><th>REMEMBER (Write)</th><th>LEARN (Training Export)</th></tr>
            </thead>
            <tbody>
              {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => (
                <tr key={s}>
                  <td><b>{s}</b></td>
                  <td><DecisionBadge decision={matrix.REVEAL?.[s] || 'ALLOW'} /></td>
                  <td><DecisionBadge decision={matrix.REMEMBER?.[s] || 'ALLOW'} /></td>
                  <td><DecisionBadge decision={matrix.LEARN?.[s] || 'GENERALIZE'} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Allowlist Registry */}
        <div className="card">
          <div className="card-title">Destinations &amp; Approved Purposes</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, fontSize: 12.5 }}>
            <div>
              <div className="section-label">Destination Allowlist</div>
              {(policy.destinations?.allow || []).map(d => <div key={d} style={{ marginBottom: 4 }}><Badge kind="ok">{d}</Badge></div>)}
              <div className="section-label">Deny List</div>
              {(policy.destinations?.deny || []).map(d => <div key={d} style={{ marginBottom: 4 }}><Badge kind="blocked">{d}</Badge></div>)}
            </div>
            <div>
              <div className="section-label">Approved Purposes</div>
              {(policy.purposes?.approved || []).map(p => <div key={p} style={{ marginBottom: 4 }}>• {PURPOSE_LABELS[p] || p}</div>)}
              <div className="section-label">Blocked Purposes</div>
              {(policy.purposes?.blocked || []).map(p => <div key={p} style={{ marginBottom: 4 }}><Badge kind="blocked">{p}</Badge></div>)}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function round100(n) {
  return Math.round(n * 100) / 100
}
