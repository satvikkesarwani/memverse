// Shared UI atoms for MEMVERSE
import React from 'react'

export function Badge({ kind = 'info', children }) {
  return <span className={`badge badge-${kind}`}>{children}</span>
}

export function SensBadge({ level }) {
  if (!level) return null
  return <span className={`sens sens-${level}`}>{level}</span>
}

export function DecisionBadge({ decision }) {
  const kind = decision === 'ALLOW' ? 'ok'
    : decision === 'BLOCK' ? 'blocked'
    : decision === 'QUARANTINE' ? 'blocked'
    : decision === 'REVOKE' ? 'blocked'
    : decision === 'EXPIRED' ? 'blocked'
    : decision === 'TRANSFORM' ? 'accent'
    : decision === 'LOCAL_ONLY' ? 'warn'
    : decision === 'REQUIRE_APPROVAL' ? 'warn'
    : 'info'
  return <Badge kind={kind}>{decision || '—'}</Badge>
}

export function StageStatusIcon({ status }) {
  const color = status === 'ok' ? '#15803d'
    : status === 'blocked' ? '#b91c1c'
    : status === 'warn' ? '#b45309'
    : status === 'error' ? '#b91c1c'
    : '#64748b'
  return (
    <span aria-hidden="true" style={{ width: 16, height: 16, borderRadius: '50%', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        {status === 'ok' && <g><circle cx="8" cy="8" r="6" fill={color} opacity="0.15" /><path d="M5.5 8.2l1.7 1.7 3.3-3.6" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></g>}
        {status === 'blocked' && <g><circle cx="8" cy="8" r="6" fill={color} opacity="0.15" /><path d="M5.4 5.4l5.2 5.2M10.6 5.4l-5.2 5.2" stroke={color} strokeWidth="1.6" strokeLinecap="round" /></g>}
        {status === 'warn' && <g><circle cx="8" cy="8" r="6" fill={color} opacity="0.15" /><path d="M8 5v3.4" stroke={color} strokeWidth="1.6" strokeLinecap="round" /><circle cx="8" cy="11" r="0.9" fill={color} /></g>}
        {status === 'error' && <g><circle cx="8" cy="8" r="6" fill={color} opacity="0.15" /><path d="M5.4 5.4l5.2 5.2M10.6 5.4l-5.2 5.2" stroke={color} strokeWidth="1.6" strokeLinecap="round" /></g>}
        {(status === 'info' || !status) && <g><circle cx="8" cy="8" r="6" fill={color} opacity="0.15" /><circle cx="8" cy="8" r="2" fill={color} /></g>}
      </svg>
    </span>
  )
}

export function ShieldIcon({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 1.5l5 2v4c0 3-2.2 5.6-5 6.5-2.8-.9-5-3.5-5-6.5v-4l5-2z" stroke="#0d9488" strokeWidth="1.4" fill="#e6f7f5" />
      <path d="M6 8l1.5 1.5L10.5 6.5" stroke="#0d9488" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function Kv({ rows }) {
  return (
    <div className="kv">
      {rows.filter(r => r.v !== undefined && r.v !== null && r.v !== '').map((r, i) => (
        <React.Fragment key={i}>
          <div className="k">{r.k}</div>
          <div className={`v ${r.mono ? 'mono' : ''}`}>{r.v}</div>
        </React.Fragment>
      ))}
    </div>
  )
}

export function SectionLabel({ children }) {
  return <div className="section-label">{children}</div>
}

export const fmtList = (arr) => Array.isArray(arr) ? arr.join(', ') : (arr || '—')
