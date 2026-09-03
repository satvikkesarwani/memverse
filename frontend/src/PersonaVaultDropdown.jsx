// PersonaVaultDropdown — Global User Persona Vault Inspector
import React, { useState, useEffect, useRef } from 'react'
import { api, shortId } from './api'
import { SensBadge } from './ui'

export default function PersonaVaultDropdown({ onVaultChange }) {
  const [isOpen, setIsOpen] = useState(false)
  const [attributes, setAttributes] = useState([])
  const [loading, setLoading] = useState(false)
  const [deletingId, setDeletingId] = useState(null)
  const dropdownRef = useRef(null)

  const fetchPersona = async () => {
    try {
      setLoading(true)
      const r = await api.persona()
      setAttributes(r.attributes || [])
    } catch (e) {
      console.error('Failed to load persona:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPersona()
  }, [])

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false)
      }
    }
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [isOpen])

  const handleDelete = async (attrId) => {
    setDeletingId(attrId)
    try {
      await api.personaDelete(attrId)
      await fetchPersona()
      if (onVaultChange) onVaultChange()
    } finally {
      setDeletingId(null)
    }
  }

  const handleWipe = async () => {
    if (!confirm('Completely wipe your Global Persona Vault and reset memory?')) return
    await api.personaWipe()
    await fetchPersona()
    if (onVaultChange) onVaultChange()
    setIsOpen(false)
  }

  // Group by category
  const categories = {}
  attributes.forEach(attr => {
    const cat = attr.category || 'GENERAL'
    if (!categories[cat]) categories[cat] = []
    categories[cat].push(attr)
  })

  return (
    <div className="vault-dropdown-wrapper" ref={dropdownRef}>
      {/* Persona Vault Trigger Button */}
      <button
        className={`vault-trigger-btn ${isOpen ? 'active' : ''}`}
        onClick={() => {
          setIsOpen(!isOpen)
          if (!isOpen) fetchPersona()
        }}
        title="View your Global Persona Vault (Personal Information stored securely)"
      >
        <span className="vault-icon">🔐</span>
        <span className="vault-label">Persona Vault</span>
        <span className="vault-count-badge">{attributes.length}</span>
        <span className="vault-arrow">{isOpen ? '▲' : '▼'}</span>
      </button>

      {/* Floating Panel */}
      {isOpen && (
        <div className="vault-panel persona-vault-panel">
          <div className="vault-panel-head">
            <div className="vault-panel-title">
              <span className="vault-badge-icon">🧠</span>
              <div>
                <div className="vault-heading">GLOBAL PERSONA VAULT</div>
                <div className="vault-subheading">Continuously auto-harvested profile under Zero-Trust boundaries</div>
              </div>
            </div>
            <div className="vault-head-actions">
              <button className="vault-mini-btn" onClick={fetchPersona} title="Refresh Persona Vault">
                ⟳
              </button>
              <button className="vault-mini-btn close" onClick={() => setIsOpen(false)} title="Close">
                ✕
              </button>
            </div>
          </div>

          <div className="vault-panel-body">
            {attributes.length > 0 ? (
              <div className="persona-categories-list">
                {Object.entries(categories).map(([catName, items]) => (
                  <div key={catName} className="persona-cat-section">
                    <div className="persona-cat-header">
                      <span className="cat-title">{catName}</span>
                      <span className="cat-badge">{items.length}</span>
                    </div>

                    <div className="vault-fields-list">
                      {items.map((item) => (
                        <div className="vault-field-card" key={item.id}>
                          <div className="vault-field-top">
                            <div className="vault-field-name">
                              <span className="vault-field-tag">{item.label || item.key}</span>
                              <SensBadge level={item.sensitivity || 'MEDIUM'} />
                            </div>
                            <button
                              className="vault-revoke-btn"
                              onClick={() => handleDelete(item.id)}
                              disabled={deletingId === item.id}
                              title="Delete this attribute from vault"
                            >
                              {deletingId === item.id ? 'Deleting…' : 'Delete'}
                            </button>
                          </div>

                          <div className="vault-field-comparison">
                            <div className="vault-val-box raw">
                              <span className="box-k">STORED IN VAULT (RAW)</span>
                              <span className="box-v mono">{item.raw_value}</span>
                            </div>
                            <span className="vault-arrow-sym">⟶</span>
                            <div className="vault-val-box egress">
                              <span className="box-k">RELEASED TO AI (SAFE GENERALIZATION)</span>
                              <span className="box-v mono">{item.sanitized_value || '[PROTECTED]'}</span>
                            </div>
                          </div>

                          <div className="vault-field-footer">
                            <span className="vault-meta-item">Policy: <b className="mono">{item.policy_action || 'GENERALIZE'}</b></span>
                            {item.source_snippet && (
                              <span className="vault-meta-item source-clip" title={item.source_snippet}>
                                Source: <i>{item.source_snippet}</i>
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="vault-empty-state">
                <div style={{ fontSize: 28, marginBottom: 8 }}>🌱</div>
                <b style={{ fontSize: 13 }}>Persona Vault is Clean & Ready</b>
                <div style={{ fontSize: 11.5, color: 'var(--muted)', marginTop: 6, lineHeight: 1.5 }}>
                  Koi dummy data nahi hai. Jaise hi aap chat me bolenge: <br />
                  <code style={{ background: 'var(--surface-alt)', padding: '2px 6px', borderRadius: 4, display: 'inline-block', marginTop: 4 }}>
                    "My name is Satvik, 6th sem CS at IIIT Pune"
                  </code>
                  <br />MEMVERSE auto-detect karke aapka <b>Real Global Persona</b> build karega!
                </div>
              </div>
            )}
          </div>

          {attributes.length > 0 && (
            <div className="vault-panel-footer">
              <span className="vault-summary-text">
                <b>{attributes.length}</b> verified attribute(s) in local vault
              </span>
              <button className="vault-wipe-btn" onClick={handleWipe}>
                🗑️ Wipe Persona Vault
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
