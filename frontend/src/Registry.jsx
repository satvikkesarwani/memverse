// Memory Registry — real backend data with revoke, read, passport views
import React, { useEffect, useState } from 'react'
import { api, fmtTime, hashShort } from './api'
import { Badge, DecisionBadge, SensBadge } from './ui'
import { ReceiptBlock } from './TraceDrawer'

const STATUS_BADGE = {
  ACTIVE: 'ok', REVOKED: 'blocked', EXPIRED: 'blocked', QUARANTINED: 'blocked', BLOCKED: 'blocked',
}

export default function Registry() {
  const [memories, setMemories] = useState([])
  const [loading, setLoading] = useState(true)
  const [detail, setDetail] = useState(null)
  const [confirmRevoke, setConfirmRevoke] = useState(null)
  const [readResult, setReadResult] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const r = await api.memories()
      setMemories(r.memories)
    } finally { setLoading(false) }
  }
  useEffect(() => { load() }, [])

  const doRevoke = async () => {
    await api.memoryRevoke(confirmRevoke.memory_id, 'Revoked from Memory Registry')
    setConfirmRevoke(null)
    load()
  }

  const doRead = async (memoryId) => {
    const r = await api.memoryRead(memoryId)
    setReadResult(r)
  }

  return (
    <div className="page">
      <div className="page-inner">
        <h2>Memory Registry</h2>
        <p className="page-sub">
          Every persisted memory with its Memory Passport. Revoking a passport makes retrieval
          fail closed — the gateway proves it.
        </p>

        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
            <div className="card-title" style={{ margin: 0 }}>Memories ({memories.length})</div>
            <div style={{ flex: 1 }} />
            <button className="btn btn-sm" onClick={load}>⟳ Refresh</button>
          </div>
          {loading ? <div className="empty-note">Loading…</div> : !memories.length ? (
            <div className="empty-note">No memories stored yet. Tell the chat something about yourself.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="tbl" style={{ tableLayout: 'auto', minWidth: 900 }}>
                <thead>
                  <tr><th>ID</th><th>Type</th><th>Sensitivity</th><th>Purpose</th><th>Consent</th><th>TTL</th><th>Passport</th><th>Status</th><th>Last access</th><th>Actions</th></tr>
                </thead>
                <tbody>
                  {memories.map(m => (
                    <tr key={m.memory_id}>
                      <td className="mono">{m.memory_id}</td>
                      <td>{m.mem_type}</td>
                      <td><SensBadge level={m.sensitivity} /></td>
                      <td>{m.purpose}</td>
                      <td>{m.consent === 'GRANTED' ? <Badge kind="ok">GRANTED</Badge> : <Badge kind="blocked">NOT GRANTED</Badge>}</td>
                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>{m.ttl_days}d · {fmtTime(m.expires_at)}</td>
                      <td>
                        <Badge kind={m.passport?.revocation_state === 'ACTIVE' ? 'accent' : 'blocked'}>
                          {m.passport?.revocation_state || '—'}
                        </Badge>
                      </td>
                      <td><Badge kind={STATUS_BADGE[m.status] || 'info'}>{m.status}</Badge></td>
                      <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{fmtTime(m.last_access)}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', gap: 5 }}>
                          <button className="btn btn-sm" onClick={() => doRead(m.memory_id)}>Read</button>
                          <button className="btn btn-sm" onClick={() => setDetail(m)}>View</button>
                          {m.status === 'ACTIVE' && (
                            <button className="btn btn-sm btn-danger" onClick={() => setConfirmRevoke(m)}>Revoke</button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {readResult && (
          <div className="card" style={{ borderColor: readResult.blocked ? '#f3cfcf' : '#c8ece7' }}>
            <div className="card-title">
              {readResult.blocked
                ? <><Badge kind="blocked">RETRIEVAL DENIED</Badge> {readResult.reason}</>
                : <><Badge kind="ok">RETRIEVAL ALLOWED</Badge> Policy-transformed context</>}
            </div>
            {!readResult.blocked && readResult.context && (
              <pre className="code-block" style={{ marginTop: 8 }}>
                {readResult.context.entries.map(e => `${e.field}: ${e.value}`).join('\n')}
              </pre>
            )}
            {readResult.trace && (
              <div style={{ marginTop: 10 }}>
                <table className="tbl">
                  <thead><tr><th>Stage</th><th>Status</th><th>Decision</th><th>Explanation</th></tr></thead>
                  <tbody>
                    {readResult.trace.stages.map(s => (
                      <tr key={s.id}>
                        <td><b>{s.name}</b></td>
                        <td><Badge kind={s.status === 'ok' ? 'ok' : s.status === 'blocked' ? 'blocked' : 'info'}>{s.status}</Badge></td>
                        <td>{s.decision}</td>
                        <td style={{ fontSize: 11.5, color: 'var(--muted)' }}>{s.explanation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {readResult.receipt && <ReceiptBlock receipt={readResult.receipt} />}
          </div>
        )}

        {detail && (
          <div className="card">
            <div className="card-title">Memory {detail.memory_id}
              <span style={{ flex: 1 }} />
              <button className="btn btn-sm" onClick={() => setDetail(null)}>Close</button>
            </div>
            <div className="raw-vs-approved" style={{ marginTop: 10 }}>
              <div className="panel-box">
                <div className="ph raw">STORED FIELDS (encrypted at rest, local-only)</div>
                <pre>{detail.payload.map(p => `${p.field}: ${p.value} → ${p.action} → ${p.output}`).join('\n')}</pre>
              </div>
              <div className="panel-box">
                <div className="ph approved">PASSPORT</div>
                {detail.passport ? (
                  <pre>{[
                    `memory: ${detail.passport.memory_id}`,
                    `sensitivity: ${detail.passport.sensitivity}`,
                    `purpose: ${detail.passport.purpose}`,
                    `consent: ${detail.passport.consent}`,
                    `destination: ${detail.passport.destination}`,
                    `ttl: ${detail.passport.ttl_days}d`,
                    `expires: ${detail.passport.expires_at}`,
                    `integrity: ${hashShort(detail.passport.integrity_hash)}`,
                    `policy: ${detail.passport.policy_version}`,
                    `state: ${detail.passport.revocation_state}`,
                  ].join('\n')}</pre>
                ) : '—'}
              </div>
            </div>
          </div>
        )}

        {confirmRevoke && (
          <div className="drawer-backdrop" onClick={() => setConfirmRevoke(null)}>
            <div className="card" style={{ width: 420, margin: 'auto', alignSelf: 'center' }} onClick={e => e.stopPropagation()}>
              <h3 style={{ margin: '0 0 6px' }}>Revoke <span className="mono">{confirmRevoke.memory_id}</span>?</h3>
              <p style={{ fontSize: 12.5, color: 'var(--muted)', margin: 0 }}>
                Passport → <b>REVOKED</b>. All future retrievals will be denied with a fail-closed receipt.
              </p>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 14 }}>
                <button className="btn" onClick={() => setConfirmRevoke(null)}>Cancel</button>
                <button className="btn btn-danger" onClick={doRevoke}>Revoke passport</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
