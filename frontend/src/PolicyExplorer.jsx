// Policy Explorer — the live policy document, rendered as readable rules
import React, { useEffect, useState } from 'react'
import { api } from './api'
import { Badge } from './ui'

const PURPOSE_LABELS = {
  answer_query: 'Answer user query', personalization: 'Personalization',
  task_execution: 'Task execution', context: 'Assistant context',
  assistance: 'Assistance', chat: 'Chat assistance',
}

export default function PolicyExplorer() {
  const [policy, setPolicy] = useState(null)

  useEffect(() => { api.policy().then(setPolicy).catch(() => {}) }, [])

  if (!policy) return <div className="page"><div className="page-inner"><div className="empty-note">Loading policy…</div></div></div>

  const fieldStrategy = policy.field_strategy || {}
  const matrix = policy.purpose_matrix || {}
  const ttl = policy.ttl_default_days || {}

  return (
    <div className="page">
      <div className="page-inner">
        <h2>Policy Explorer</h2>
        <p className="page-sub">
          Decisions are made by this versioned, typed policy — not by the model. The same input +
          purpose + destination + passport always produces the same decision.
        </p>

        <div className="card">
          <div className="card-title">MEMVERSE POLICY <Badge kind="accent">{policy.version}</Badge>
            <Badge kind="info">{policy.name}</Badge></div>
          <p className="card-sub" style={{ marginBottom: 0 }}>Updated {policy.updated} · served from the gateway via <code>/api/policies/current</code></p>
        </div>

        <div className="card">
          <div className="card-title">Rules (evaluated in order, first match wins)</div>
          <table className="tbl">
            <thead><tr><th>Rule</th><th>Condition</th><th>Action</th><th>Rationale</th></tr></thead>
            <tbody>
              {(policy.rules || []).map(r => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td><code>IF</code> {Object.entries(r.if).map(([k, v]) => `${k} = ${JSON.stringify(v)}`).join(' AND ')}</td>
                  <td><Badge kind={r.then === 'BLOCK' ? 'blocked' : r.then === 'QUARANTINE' ? 'blocked' : 'accent'}>{r.then}</Badge></td>
                  <td style={{ fontSize: 11.5, color: 'var(--muted)' }}>{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          <div className="card-title">Sensitivity × operation matrix (REVEAL / REMEMBER)</div>
          <table className="tbl">
            <thead><tr><th>Sensitivity</th><th>REVEAL (read → model)</th><th>REMEMBER (write)</th><th>LEARN</th></tr></thead>
            <tbody>
              {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => (
                <tr key={s}>
                  <td><b>{s}</b></td>
                  <td><Badge kind={matrix.REVEAL?.[s] === 'ALLOW' ? 'ok' : matrix.REVEAL?.[s] === 'BLOCK' ? 'blocked' : 'accent'}>{matrix.REVEAL?.[s] || '—'}</Badge></td>
                  <td><Badge kind={matrix.REMEMBER?.[s] === 'ALLOW' ? 'ok' : matrix.REMEMBER?.[s] === 'BLOCK' ? 'blocked' : 'accent'}>{matrix.REMEMBER?.[s] || '—'}</Badge></td>
                  <td><Badge kind="blocked">{matrix.LEARN?.['*'] || 'BLOCK'}</Badge> <span style={{ fontSize: 11, color: 'var(--muted)' }}>extension path</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          <div className="card-title">Field-level strategy</div>
          <table className="tbl">
            <thead><tr><th>Field type</th><th>On TRANSFORM</th><th>On ALLOW</th><th>On BLOCK</th></tr></thead>
            <tbody>
              {Object.entries(fieldStrategy).map(([type, strat]) => (
                <tr key={type}>
                  <td><b>{type}</b></td>
                  <td><Badge kind={strat.TRANSFORM === 'BLOCK' ? 'blocked' : strat.TRANSFORM === 'ALLOW' ? 'ok' : 'accent'}>{strat.TRANSFORM}</Badge></td>
                  <td><Badge kind={strat.ALLOW === 'BLOCK' ? 'blocked' : 'ok'}>{strat.ALLOW}</Badge></td>
                  <td><Badge kind="blocked">{strat.BLOCK}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          <div className="card-title">Destinations &amp; purposes</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, fontSize: 12.5 }}>
            <div>
              <div className="section-label">Destination allowlist</div>
              {(policy.destinations?.allow || []).map(d => <div key={d}><Badge kind="ok">{d}</Badge></div>)}
              <div className="section-label">Deny list</div>
              {(policy.destinations?.deny || []).map(d => <div key={d}><Badge kind="blocked">{d}</Badge></div>)}
            </div>
            <div>
              <div className="section-label">Approved purposes</div>
              {(policy.purposes?.approved || []).map(p => <div key={p}>{PURPOSE_LABELS[p] || p}</div>)}
              <div className="section-label">Blocked purposes</div>
              {(policy.purposes?.blocked || []).map(p => <div key={p}><Badge kind="blocked">{p}</Badge></div>)}
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            <div className="section-label">Default TTL by sensitivity</div>
            {Object.entries(ttl).map(([s, d]) => (
              <span key={s} style={{ marginRight: 10, fontSize: 12.5 }}><b>{s}</b>: {d} day{d === 1 ? '' : 's'}</span>
            ))}
          </div>
        </div>

        <div className="card" style={{ background: 'var(--accent-softer)', borderColor: '#c8ece7' }}>
          <b>Remember / Reveal / Learn</b>
          <p style={{ fontSize: 12.5, color: 'var(--ink-2)', margin: '6px 0 0' }}>
            <b>REMEMBER</b> — what may be stored (write pipeline with passport) · <b>REVEAL</b> — what may be
            retrieved and sent to the model (read pipeline with transformation) · <b>LEARN</b> — what may be reused
            for training/analytics: <Badge kind="blocked">BLOCKED in this prototype — extension path</Badge>.
            No federated learning or secure aggregation is claimed or implemented.
          </p>
        </div>
      </div>
    </div>
  )
}
