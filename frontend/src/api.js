// MEMVERSE API client — talks ONLY to the gateway. Never to NVIDIA.

async function jfetch(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || JSON.stringify(body)
    } catch { /* ignore */ }
    throw new Error(`${res.status}: ${detail}`)
  }
  return res.json()
}

export const api = {
  status: () => jfetch('/api/status'),
  chat: (prompt, conversationId, purpose = 'answer_query', destination = 'nvidia') =>
    jfetch('/api/chat', { method: 'POST', body: JSON.stringify({ prompt, conversation_id: conversationId, purpose, destination }) }),
  messages: (conversationId = '') => jfetch(`/api/messages?conversation_id=${conversationId}`),
  memoryWrite: (text, purpose = 'personalization', destination = 'assistant_context', ttlDays = null) =>
    jfetch('/api/memory/write', { method: 'POST', body: JSON.stringify({ text, purpose, destination, consent: true, ttl_days: ttlDays }) }),
  memoryRead: (memoryId) =>
    jfetch('/api/memory/read', { method: 'POST', body: JSON.stringify({ memory_id: memoryId }) }),
  memoryRevoke: (memoryId, reason = 'Revoked by user') =>
    jfetch('/api/memory/revoke', { method: 'POST', body: JSON.stringify({ memory_id: memoryId, reason }) }),
  memories: () => jfetch('/api/memories'),
  events: (limit = 200) => jfetch(`/api/events?limit=${limit}`),
  receipts: (limit = 200) => jfetch(`/api/receipts?limit=${limit}`),
  receipt: (id) => jfetch(`/api/receipts/${id}`),
  receiptVerify: (id) => jfetch(`/api/receipts/${id}/verify`, { method: 'POST' }),
  trace: (id) => jfetch(`/api/traces/${id}`),
  policy: () => jfetch('/api/policies/current'),
  securityTest: (name) => jfetch('/api/security/test', { method: 'POST', body: JSON.stringify({ name }) }),
  securityRunAll: () => jfetch('/api/security/run-all', { method: 'POST' }),
  demoSeed: () => jfetch('/api/demo/seed', { method: 'POST' }),
  demoSeedTask: () => jfetch('/api/demo/seed-task', { method: 'POST' }),
  demoReset: () => jfetch('/api/demo/reset', { method: 'POST' }),
}

export const fmtMs = (ms) => (ms == null ? '—' : ms < 1 ? '<1 ms' : `${Math.round(ms)} ms`)
export const fmtTime = (iso) => {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch { return iso }
}
export const shortId = (id) => (id ? (id.length > 16 ? id.slice(0, 14) + '…' : id) : '—')
export const hashShort = (h) => (h ? h.slice(0, 12) + '…' : '—')
