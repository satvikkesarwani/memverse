// App shell — sidebar navigation + pages
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
  { id: 'chat', label: 'Chat', icon: '', group: 'Product' },
  { id: 'demo', label: 'Guided Demo', icon: '', group: 'Product' },
  { id: 'registry', label: 'Memory Registry', icon: '', group: 'Security' },
  { id: 'policy', label: 'Policy Explorer', icon: '', group: 'Security' },
  { id: 'lab', label: 'Security Lab', icon: '', group: 'Security' },
  { id: 'ledger', label: 'Event Ledger', icon: '', group: 'Evidence' },
  { id: 'claims', label: 'Claim Coverage', icon: '', group: 'Evidence' },
  { id: 'playground', label: 'Memory Playground', icon: '', group: 'Evidence' },
  { id: 'architecture', label: 'How MEMVERSE Works', icon: '', group: 'Evidence' },
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
            <div className="brand-sub">Zero-Trust Memory for AI</div>
          </div>
        </div>
        <nav className="nav" aria-label="Main navigation">
          {groups.map(g => (
            <React.Fragment key={g}>
              <div className="nav-label">{g}</div>
              {NAV.filter(n => n.group === g).map(n => (
                <button key={n.id} className={`nav-item ${page === n.id ? 'active' : ''}`}
                  onClick={() => setPage(n.id)} aria-current={page === n.id ? 'page' : undefined}>
                  <span aria-hidden="true">{n.icon}</span> {n.label}
                </button>
              ))}
            </React.Fragment>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--muted)' }}>
            <ShieldIcon /> {status ? (status.llm || 'gateway') : 'connecting…'}
          </div>
          <button className="btn btn-sm" onClick={loadDemo}>⬇ Load Demo Data</button>
          <button className="btn btn-sm" onClick={reset}>⟲ Reset Demo</button>
        </div>
      </aside>

      <main className="main">
        {page === 'chat' && (
          <ChatView conversationId={conversationId} setConversationId={setConversationId}
            onMessagesChanged={msgs => setMsgCount(msgs.length)} isDemo={status ? status.demo : true} />
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
