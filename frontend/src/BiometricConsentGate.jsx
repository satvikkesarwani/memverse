import React, { useState } from 'react'
import { Badge } from './ui'

export default function BiometricConsentGate({
  scanResult,
  filename,
  purposeHint,
  onConsent,
  onCancel,
}) {
  const hasFace = scanResult.hasFace
  const faceCount = scanResult.faceCount
  const thumbnailDataUrl = scanResult.thumbnailDataUrl
  const sanitizedThumb = scanResult.sanitizedThumbnail || thumbnailDataUrl

  // State for mode: 'anonymized' (default) vs 'raw'
  const [redactionMode, setRedactionMode] = useState('anonymized')

  const isAnonymized = redactionMode === 'anonymized'
  const dataTypeLabel = hasFace 
    ? (isAnonymized ? '🛡️ BIOMETRIC (Face Pixelated / Redacted)' : '⚠️ BIOMETRIC (Raw Face Exposed)')
    : '🖼️ General Image'
  const dataTypeColor = isAnonymized ? '#15803d' : '#b91c1c'
  const consentLabel = isAnonymized ? 'Send Anonymized Image (Face Blurred)' : 'Send Raw Image (1-Request TTL)'

  return (
    <div className="consent-overlay" aria-modal="true" role="dialog" aria-label="Biometric consent gate">
      <div className="consent-modal" role="document" style={{ maxWidth: '560px' }}>
        <div className="consent-header">
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '20px' }}>🛡️</span>
            <span>MEMVERSE BIOMETRIC PRIVACY GATE</span>
          </span>
          <span style={{ fontSize: '12px', color: 'var(--muted)', marginLeft: 'auto' }}>
            {faceCount} Face{faceCount !== 1 ? 's' : ''} Detected
          </span>
        </div>

        {hasFace && (
          <div className="consent-warning" style={{
            background: 'var(--amber-bg)',
            borderColor: '#b45309',
            color: '#b45309',
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            margin: '12px 0',
            fontSize: '12px',
            lineHeight: 1.5,
          }}>
            <b>⚠️ Biometric Notice:</b> Facial structure is irreversible biometric identity. MEMVERSE client-side scanner detected a face. By default, your facial region will be <b>pixelated on your browser</b> before leaving your device.
          </div>
        )}

        {/* Mode Selector Toggle */}
        {hasFace && (
          <div style={{
            display: 'flex',
            gap: '8px',
            background: 'var(--surface-alt)',
            padding: '4px',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '14px',
          }}>
            <button
              type="button"
              onClick={() => setRedactionMode('anonymized')}
              style={{
                flex: 1,
                padding: '8px 12px',
                border: 'none',
                borderRadius: 'var(--radius-xs)',
                background: isAnonymized ? 'var(--green-bg)' : 'transparent',
                color: isAnonymized ? 'var(--green)' : 'var(--muted)',
                fontWeight: isAnonymized ? 700 : 500,
                fontSize: '12px',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                borderWidth: '1.5px',
                borderStyle: 'solid',
                borderColor: isAnonymized ? 'var(--green)' : 'transparent',
              }}
            >
              🛡️ Anonymize Face (Recommended)
            </button>
            <button
              type="button"
              onClick={() => setRedactionMode('raw')}
              style={{
                flex: 1,
                padding: '8px 12px',
                border: 'none',
                borderRadius: 'var(--radius-xs)',
                background: !isAnonymized ? 'var(--red-bg)' : 'transparent',
                color: !isAnonymized ? 'var(--red)' : 'var(--muted)',
                fontWeight: !isAnonymized ? 700 : 500,
                fontSize: '12px',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                borderWidth: '1.5px',
                borderStyle: 'solid',
                borderColor: !isAnonymized ? 'var(--red)' : 'transparent',
              }}
            >
              ⚠️ Send Raw Face (Portrait / Avatar)
            </button>
          </div>
        )}

        {/* Before / After Transparency Comparison */}
        {hasFace && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '12px',
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px',
            marginBottom: '14px',
          }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '11px', color: 'var(--muted)', fontWeight: 600, marginBottom: '6px' }}>
                RAW CLIENT UPLOAD
              </div>
              <img
                src={thumbnailDataUrl}
                alt="Raw Preview"
                style={{
                  width: '80px',
                  height: '80px',
                  objectFit: 'cover',
                  borderRadius: 'var(--radius-xs)',
                  border: '1px solid var(--border)',
                }}
              />
              <div style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '4px' }}>
                Full Facial Identity
              </div>
            </div>

            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '11px', color: isAnonymized ? 'var(--green)' : 'var(--red)', fontWeight: 600, marginBottom: '6px' }}>
                {isAnonymized ? 'EGRESS WIRE (SANITIZED)' : 'EGRESS WIRE (EXPOSED)'}
              </div>
              <img
                src={isAnonymized ? sanitizedThumb : thumbnailDataUrl}
                alt="Egress Wire Preview"
                style={{
                  width: '80px',
                  height: '80px',
                  objectFit: 'cover',
                  borderRadius: 'var(--radius-xs)',
                  border: `2px solid ${isAnonymized ? 'var(--green)' : 'var(--red)'}`,
                }}
              />
              <div style={{ fontSize: '10px', color: isAnonymized ? 'var(--green)' : 'var(--red)', fontWeight: 600, marginTop: '4px' }}>
                {isAnonymized ? '✅ 8x8 Mosaic Redacted' : '⚠️ Raw Pixels Sent'}
              </div>
            </div>
          </div>
        )}

        {/* Fact Grid */}
        <div className="consent-facts" style={{ marginBottom: '14px' }}>
          <div className="consent-fact-row">
            <span className="consent-fact-row-span-first">File:</span>
            <span>{filename}</span>
          </div>
          <div className="consent-fact-row">
            <span className="consent-fact-row-span-first">Egress State:</span>
            <span style={{ color: dataTypeColor, fontWeight: 700 }}>{dataTypeLabel}</span>
          </div>
          <div className="consent-fact-row">
            <span className="consent-fact-row-span-first">EXIF Metadata:</span>
            <span style={{ color: 'var(--green)', fontWeight: 600 }}>100% STRIPPED (GPS/Device Removed)</span>
          </div>
          <div className="consent-fact-row">
            <span className="consent-fact-row-span-first">Database Retention:</span>
            <span style={{ color: 'var(--green)', fontWeight: 600 }}>ZERO RETENTION (Never Saved in DB)</span>
          </div>
          <div className="consent-fact-row">
            <span className="consent-fact-row-span-first">Passport TTL:</span>
            <span style={{ color: 'var(--green)', fontWeight: 600 }}>1 Request — Auto Expires</span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="consent-actions" style={{ display: 'flex', gap: '10px' }}>
          <button
            className="btn btn-secondary"
            onClick={onCancel}
            style={{ flex: '1', padding: '10px' }}
          >
            ✕ Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={() => onConsent(isAnonymized)}
            style={{
              flex: '2',
              padding: '10px',
              background: isAnonymized ? 'var(--green)' : '#dc2626',
              borderColor: isAnonymized ? 'var(--green)' : '#dc2626',
              color: '#ffffff',
              fontWeight: 700,
            }}
          >
            ✓ {consentLabel}
          </button>
        </div>
      </div>
    </div>
  )
}