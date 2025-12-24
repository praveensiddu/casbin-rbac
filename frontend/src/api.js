const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

export async function login(username, password) {
  const res = await fetch(`${API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(data?.detail || 'Login failed')
  }
  return data
}

export async function apiRequest(path, { method = 'GET', token, body } = {}) {
  const headers = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  })

  const text = await res.text()
  let parsed
  try {
    parsed = text ? JSON.parse(text) : null
  } catch {
    parsed = text
  }

  if (!res.ok) {
    const msg = typeof parsed === 'object' && parsed !== null ? JSON.stringify(parsed) : String(parsed)
    throw new Error(msg || `Request failed: ${res.status}`)
  }

  return parsed
}
