// IdentityVaultDropdown — Live Personal Data Inspector & Memory Vault
import React, { useState, useEffect, useRef } from 'react'
import { api, fmtTime, shortId } from './api'
import { Badge, SensBadge } from './ui'

export default function IdentityVaultDropdown({ memories, onRefreshMemories }) {
  const [isOpen, setIsOpen] = useState(false)
  const [revokingId, setRevokingId] = useState(null)
  const dropdownRef = useRef(null)

  // Filter active memories
  const activeMemories = memories.filter(m => m.status === 'ACTIVE' && m.passport?.revocation_state === 'ACTIVE')
  
  // Aggregate all stored fields
  const allFields = []
  activeMemories.forEach(m => {
    (m.payload || []).forEach(f => {
      allFields.push({
        ...f,
        memory_id: m.memory_id,
        ttl_days: m.ttl_days,
        created_at: m.created_at,
        purpose: m.purpose,
      })
    })
  })

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

  const handleRevoke = async (memoryId) => {
    setRevokingId(memoryId)
    try {
      await api.memoryRevoke(memoryId, 'Revoked from Identity Vault dropdown')
      if (onRefreshMemories) await onRefreshMemories()
    } finally {
      setRevokingId(null)
    }
  }

  const handleWipeAll = async () => {
    if (!confirm('Wipe all stored memories and reset your identity vault?')) return
    await api.demoReset()
    if (onRefreshMemories) await onRefreshMemories()
    setIsOpen(false)
  }

  return (
    <div className="vault-dropdown-wrapper" ref={dropdownRef}>
      {/* Dropdown Trigger Pill */}
      <button
        className={`vault-trigger-btn ${isOpen ? 'active' : ''}`}
        onClick={() => setIsOpen(!isOpen)}
        title="View personal data currently stored in MEMVERSE memory"
      >
        <span className="vault-icon">🔐</span>
        <span className="vault-label">Identity Vault</span>
        <span className="vault-count-badge">{allFields.length}</span>
        <span className="vault-arrow">{isOpen ? '▲' : '▼'}</span>
      </button>

      {/* Dropdown Floating Panel */}
      {isOpen && (
        <div className="vault-panel">
          <div className="vault-panel-head">
            <div className="vault-panel-title">
              <span className="vault-badge-icon">🛡️</span>
              <div>
                <div className="vault-heading">LIVE IDENTITY VAULT</div>
                <div className="vault-subheading">Personal data currently held under active Zero-Trust Passports</div>
              </div>
            </div>
            <div className="vault-head-actions">
              <button className="vault-mini-btn" onClick={onRefreshMemories} title="Refresh Vault">
                ⟳
              </button>
              <button className="vault-mini-btn close" onClick={() => setIsOpen(false)} title="Close">
                ✕
              </button>
            </div>
          </div>

          <div className="vault-panel-body">
            {allFields.length > 0 ? (
              <div className="vault-fields-list">
                {allFields.map((f, idx) => (
                  <div className="vault-field-card" key={idx}>
                    <div className="vault-field-top">
                      <div className="vault-field-name">
                        <span className="vault-field-tag">{f.field || 'ATTRIBUTE'}</span>
                        <SensBadge level={f.sensitivity || 'MEDIUM'} />
                      </div>
                      <button
                        className="vault-revoke-btn"
                        onClick={() => handleRevoke(f.memory_id)}
                        disabled={revokingId === f.memory_id}
                        title="Revoke this passport immediately"
                      >
                        {revokingId === f.memory_id ? 'Revoking…' : 'Revoke'}
                      </button>
                    </div>

                    <div className="vault-field-comparison">
                      <div className="vault-val-box raw">
                        <span className="box-k">STORED IN VAULT (RAW)</span>
                        <span className="box-v mono">{f.value || f.raw_value}</span>
                      </div>
                      <span className="vault-arrow-sym">⟶</span>
                      <div className="vault-val-box egress">
                        <span className="box-k">RELEASED TO AI (CLEANED)</span>
                        <span className="box-v mono">{f.output || '[PROTECTED]'}</span>
                      </div>
                    </div>

                    <div className="vault-field-footer">
                      <span className="vault-meta-item">Passport: <b className="mono">{shortId(f.memory_id)}</b></span>
                      <span className="vault-meta-item">Action: <b className="mono">{f.action || 'TRANSFORM'}</b></span>
                      <span className="vault-meta-item">TTL: <b>{f.ttl_days}d</b></span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="vault-empty-state">
                <div style={{ fontSize: 24, marginBottom: 6 }}>📭</div>
                <b>No Active Personal Data in Memory</b>
                <div style={{ fontSize: 11.5, color: 'var(--muted)', marginTop: 4 }}>
                  Send a prompt like <i>"My name is Satvik, 6th sem student at IIIT Pune"</i> to see your identity safely stored under a Zero-Trust Passport.
                </div>
              </div>
            )}
          </div>

          {allFields.length > 0 && (
            <div className="vault-panel-footer">
              <span className="vault-summary-text">
                <b>{activeMemories.length}</b> active passport(s) · <b>{allFields.length}</b> protected attribute(s)
              </span>
              <button className="vault-wipe-btn" onClick={handleWipeAll}>
                🗑️ Wipe All Data
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
