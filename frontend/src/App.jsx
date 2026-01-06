import React, { useMemo, useState } from 'react'
import { apiRequest, login } from './api'

function Section({ title, children }) {
  return (
    <div className="section">
      <div className="sectionTitle">{title}</div>
      {children}
    </div>
  )
}

export default function App() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('alice')
  const [token, setToken] = useState('')
  const [role, setRole] = useState('')
  const [output, setOutput] = useState('')
  const [error, setError] = useState('')

  const isAuthed = useMemo(() => Boolean(token), [token])

  async function onLogin(e) {
    e.preventDefault()
    setError('')
    setOutput('')
    try {
      const data = await login(username, password)
      setToken(data.access_token)
      setRole(data.role)
      setOutput(JSON.stringify(data, null, 2))
    } catch (err) {
      setError(err.message)
    }
  }

  async function callEndpoint(path, method) {
    setError('')
    setOutput('')
    try {
      const data = await apiRequest(path, { method, token })
      setOutput(JSON.stringify(data, null, 2))
    } catch (err) {
      setError(err.message)
    }
  }

  function logout() {
    setToken('')
    setRole('')
    setOutput('')
    setError('')
  }

  return (
    <div className="page">
      <div className="card">
        <div className="title">Casbin RBAC Demo (FastAPI + React)</div>
        <div className="subtitle">
          Users: alice/admin, bob/editor, eve/viewer (password equals username)
        </div>

        <Section title="Login">
          <form className="row" onSubmit={onLogin}>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" />
            <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" type="password" />
            <button type="submit">Login</button>
            <button type="button" onClick={logout} disabled={!isAuthed}>
              Logout
            </button>
          </form>
          <div className="row small">
            <div><b>Token:</b> {token || '-'}</div>
            <div><b>Role:</b> {role || '-'}</div>
          </div>
        </Section>

        <Section title="Try endpoints">
          <div className="grid">
            <button disabled={!isAuthed} onClick={() => callEndpoint('/me', 'GET')}>GET /me</button>
            <button disabled={!isAuthed} onClick={() => callEndpoint('/documents/123', 'GET')}>GET /documents/123</button>
            <button disabled={!isAuthed} onClick={() => callEndpoint('/documents/123', 'PUT')}>PUT /documents/123</button>
            <button disabled={!isAuthed} onClick={() => callEndpoint('/documents/123', 'DELETE')}>DELETE /documents/123</button>
          </div>
        </Section>

        <Section title="Result">
          {error ? <pre className="error">{error}</pre> : null}
          {output ? <pre className="output">{output}</pre> : <div className="muted">No output yet.</div>}
        </Section>
      </div>
    </div>
  )
}
