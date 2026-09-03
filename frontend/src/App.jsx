// App shell — Minimalist & Brutalist Zero-Trust Security Console
import React, { useEffect, useState } from 'react'
import { api } from './api'
import ChatView from './ChatView'
import Registry from './Registry'
import PolicyExplorer from './PolicyExplorer'
import SecurityLab from './SecurityLab'
import Ledger from './Ledger'
import Playground from './Playground'
import Architecture from './Architecture'
import GuidedDemo from './GuidedDemo'
import ClaimsCoverage from './ClaimsCoverage'
import { ShieldIcon } from './ui'

const NAV = [
  { id: 'chat', label: 'Chat Assistant', code: '01', group: 'Interface' },
  { id: 'demo', label: 'Guided Demo', code: '02', group: 'Interface' },
  { id: 'registry', label: 'Memory Registry', code: '03', group: 'Security Engine' },
  { id: 'policy', label: 'Policy Explorer', code: '04', group: 'Security Engine' },
  { id: 'lab', label: 'Security Lab', code: '05', group: 'Security Engine' },
  { id: 'ledger', label: 'Event Ledger', code: '06', group: 'Audit & Proof' },
  { id: 'claims', label: 'Claim Coverage', code: '07', group: 'Audit & Proof' },
  { id: 'playground', label: 'Memory Playground', code: '08', group: 'Audit & Proof' },
  { id: 'architecture', label: 'How MEMVERSE Works', code: '09', group: 'Audit & Proof' },
]

export default function App() {
  const [page, setPage] = useState('chat')
  const [status, setStatus] = useState(null)
  const [conversationId, setConversationId] = useState('')
  const [seeded, setSeeded] = useState(false)
  const [msgCount, setMsgCount] = useState(0)

  useEffect(() => {
    api.status().then(setStatus).catch(() => setStatus({ llm: 'unavailable' }))
    // auto-seed demo profile on first run
    api.memories().then(r => {
      if (!r.memories.length) {
        api.demoSeed().then(() => setSeeded(true)).catch(() => {})
      }
    }).catch(() => {})
  }, [])

  const reset = async () => {
    await api.demoReset()
    setSeeded(false)
    setConversationId('')
    setMsgCount(0)
    window.location.reload()
  }

  const loadDemo = async () => {
    await api.demoReset()
    await api.demoSeed()
    setSeeded(true)
    setConversationId('')
    setMsgCount(0)
    window.location.reload()
  }

  const groups = [...new Set(NAV.map(n => n.group))]

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">M</div>
          <div>
            <div className="brand-name">MEMVERSE</div>
            <div className="brand-sub">Zero-Trust Firewall</div>
          </div>
        </div>

        <nav className="nav" aria-label="Main navigation">
          {groups.map(g => (
            <React.Fragment key={g}>
              <div className="nav-label">{g}</div>
              {NAV.filter(n => n.group === g).map(n => (
                <button
                  key={n.id}
                  className={`nav-item ${page === n.id ? 'active' : ''}`}
                  onClick={() => setPage(n.id)}
                  aria-current={page === n.id ? 'page' : undefined}
                >
                  <span className="mono" style={{ fontSize: 10, opacity: page === n.id ? 1 : 0.6 }}>{n.code}</span>
                  <span>{n.label}</span>
                </button>
              ))}
            </React.Fragment>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="telemetry-row">
            <ShieldIcon size={14} />
            <span style={{ textTransform: 'uppercase' }}>
              {status ? (status.llm || 'GATEWAY ACTIVE') : 'CONNECTING…'}
            </span>
          </div>
          <button className="btn btn-sm" onClick={loadDemo}>⬇ Load Demo Data</button>
          <button className="btn btn-sm" onClick={reset}>⟲ Reset Demo</button>
        </div>
      </aside>

      <main className="main">
        {page === 'chat' && (
          <ChatView
            conversationId={conversationId}
            setConversationId={setConversationId}
            onMessagesChanged={msgs => setMsgCount(msgs.length)}
            isDemo={status ? status.demo : true}
          />
        )}
        {page === 'demo' && <GuidedDemo goChat={() => setPage('chat')} />}
        {page === 'registry' && <Registry />}
        {page === 'policy' && <PolicyExplorer />}
        {page === 'lab' && <SecurityLab />}
        {page === 'ledger' && <Ledger />}
        {page === 'claims' && <ClaimsCoverage />}
        {page === 'playground' && <Playground />}
        {page === 'architecture' && <Architecture />}
      </main>
    </div>
  )
}
