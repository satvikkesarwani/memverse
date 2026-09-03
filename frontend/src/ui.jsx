// Shared UI atoms for MEMVERSE — Minimalist Brutalist Console
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
    : '#71717a'
  return (
    <span aria-hidden="true" style={{ width: 16, height: 16, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        {status === 'ok' && (
          <g>
            <rect x="1" y="1" width="14" height="14" rx="2" fill="#f0fdf4" stroke={color} strokeWidth="1.5" />
            <path d="M4.5 8l2.5 2.5 4.5-5" stroke={color} strokeWidth="1.8" strokeLinecap="square" strokeLinejoin="miter" />
          </g>
        )}
        {(status === 'blocked' || status === 'error') && (
          <g>
            <rect x="1" y="1" width="14" height="14" rx="2" fill="#fef2f2" stroke={color} strokeWidth="1.5" />
            <path d="M5 5l6 6M11 5l-6 6" stroke={color} strokeWidth="1.8" strokeLinecap="square" />
          </g>
        )}
        {status === 'warn' && (
          <g>
            <rect x="1" y="1" width="14" height="14" rx="2" fill="#fffbeb" stroke={color} strokeWidth="1.5" />
            <path d="M8 4.5v4" stroke={color} strokeWidth="1.8" strokeLinecap="square" />
            <rect x="7.2" y="10" width="1.6" height="1.6" fill={color} />
          </g>
        )}
        {(status === 'info' || !status) && (
          <g>
            <rect x="1" y="1" width="14" height="14" rx="2" fill="#f4f5f7" stroke={color} strokeWidth="1.5" />
            <rect x="6.5" y="6.5" width="3" height="3" fill={color} />
          </g>
        )}
      </svg>
    </span>
  )
}

export function ShieldIcon({ size = 15 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 1.5l5 2.2v4.2c0 3.2-2.2 5.8-5 6.6-2.8-.8-5-3.4-5-6.6V3.7l5-2.2z" stroke="#090a0c" strokeWidth="1.5" fill="#f0fdfa" />
      <path d="M5.5 8l2 2 3.5-4" stroke="#0f766e" strokeWidth="1.6" strokeLinecap="square" strokeLinejoin="miter" />
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
