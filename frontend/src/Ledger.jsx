// Event Ledger — chronological, append-only receipt history with verification
import React, { useEffect, useState } from 'react'
import { api, fmtTime, shortId } from './api'
import { Badge, DecisionBadge } from './ui'
import { ReceiptBlock } from './TraceDrawer'

const EVENT_ICON = {
  MEMORY_WRITE: '', CHAT_REQUEST: '', MEMORY_READ: '', REVOKE: '', QUARANTINE: '', EXPIRE: '',
}

export default function Ledger() {
  const [events, setEvents] = useState([])
  const [selected, setSelected] = useState(null)
  const [receipt, setReceipt] = useState(null)

  useEffect(() => {
    api.events().then(r => setEvents(r.events)).catch(() => {})
  }, [])

  const open = async (ev) => {
    setSelected(ev)
    try {
      const r = await api.receipt(ev.id)
      setReceipt({ ...r.data, event_id: ev.id, previous_event_hash: r.previous_event_hash, event_hash: r.event_hash })
    } catch { setReceipt(null) }
  }

  return (
    <div className="page">
      <div className="page-inner">
        <h2>Event Ledger</h2>
        <p className="page-sub">
          Append-only, hash-linked history. Every allow / block / transform / quarantine / revoke
          created a receipt. Click an event to inspect and verify its integrity.
        </p>

        <div className="card" style={{ padding: 0 }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="tbl">
              <thead>
                <tr><th>#</th><th>Event</th><th>Timestamp</th><th>Decision</th><th>Policy</th><th>Memory</th><th>Destination</th><th>Receipt</th></tr>
              </thead>
              <tbody>
                {events.length === 0 && (
                  <tr><td colSpan="8"><div className="empty-note">No events yet — the ledger is empty.</div></td></tr>
                )}
                {events.map(ev => (
                  <tr key={ev.id} className="clickable" onClick={() => open(ev)} tabIndex="0"
                    onKeyDown={e => { if (e.key === 'Enter') open(ev) }}
                    aria-label={`Open receipt for ${ev.event_type}`}>
                    <td className="mono">{shortId(ev.id)}</td>
                    <td>{EVENT_ICON[ev.event_type] || '•'} <b>{ev.event_type}</b></td>
                    <td className="mono" style={{ fontSize: 11 }}>{fmtTime(ev.ts)}</td>
                    <td><DecisionBadge decision={ev.decision} /></td>
                    <td className="mono">{ev.policy_version}</td>
                    <td className="mono">{shortId(ev.memory_id)}</td>
                    <td className="mono">{ev.destination}</td>
                    <td><Badge kind="gold">receipt</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card" style={{ fontSize: 12, color: 'var(--muted)' }}>
          <b>How the chain works:</b> every receipt stores <code className="mono">previous_event_hash</code> and
          its own <code className="mono">event_hash = SHA256(canonical_event_data | previous_hash)</code>.
          Verification recomputes the hash and walks the chain back to GENESIS — tampering anywhere breaks it.
        </div>

        {selected && (
          <div className="drawer-backdrop" onClick={() => setSelected(null)}>
            <div className="drawer" onClick={e => e.stopPropagation()}>
              <div className="drawer-head">
                <h3>Event {shortId(selected.id)}</h3>
                <span style={{ fontSize: 11, color: 'var(--muted)' }}>{selected.event_type} · {fmtTime(selected.ts)}</span>
                <button className="drawer-close" onClick={() => setSelected(null)} aria-label="Close">×</button>
              </div>
              <div className="drawer-body">
                <div className="card" style={{ padding: 0 }}>
                  <div style={{ padding: '14px 18px' }}>
                    <div className="kv">
                      <div className="k">Event ID</div><div className="v mono">{selected.id}</div>
                      <div className="k">Event type</div><div className="v">{selected.event_type}</div>
                      <div className="k">Timestamp</div><div className="v">{fmtTime(selected.ts)}</div>
                      <div className="k">Decision</div><div className="v"><DecisionBadge decision={selected.decision} /></div>
                      <div className="k">Policy</div><div className="v mono">{selected.policy_version}</div>
                      <div className="k">Memory</div><div className="v mono">{selected.memory_id || '—'}</div>
                      <div className="k">Destination</div><div className="v mono">{selected.destination}</div>
                      <div className="k">Latency</div><div className="v mono">{selected.latency_ms != null ? `${Math.round(selected.latency_ms)} ms` : '—'}</div>
                    </div>
                    {receipt && <ReceiptBlock receipt={receipt} />}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
