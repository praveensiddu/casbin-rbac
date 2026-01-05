const { useMemo, useState } = React;

async function login(username, password) {
  const res = await fetch(`${window.API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data?.detail || 'Login failed');
  }
  return data;
}

async function apiRequest(path, { method = 'GET', token, body } = {}) {
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${window.API_URL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }

  if (!res.ok) {
    const msg = typeof parsed === 'object' && parsed !== null ? JSON.stringify(parsed) : String(parsed);
    throw new Error(msg || `Request failed: ${res.status}`);
  }

  return parsed;
}

function Section({ title, children }) {
  return (
    <div className="section">
      <div className="sectionTitle">{title}</div>
      {children}
    </div>
  );
}

function App() {
  const [username, setUsername] = useState('alice');
  const [password, setPassword] = useState('alice');
  const [token, setToken] = useState('');
  const [groups, setGroups] = useState([]);
  const [roles, setRoles] = useState([]);
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [tab, setTab] = useState('demo');

  const [rmRows, setRmRows] = useState([]);
  const [rmGroups, setRmGroups] = useState([]);
  const [rmGroup, setRmGroup] = useState('');
  const [rmRole, setRmRole] = useState('viewer');
  const [rmAppId, setRmAppId] = useState('123');

  const [rmViewallGroup, setRmViewallGroup] = useState('');
  const [rmViewallAccess, setRmViewallAccess] = useState([]);

  const [arRows, setArRows] = useState([]);
  const [arAppId, setArAppId] = useState('');
  const [arRole, setArRole] = useState('viewer');
  const [arMyRequests, setArMyRequests] = useState([]);
  const [arAllRequests, setArAllRequests] = useState([]);

  const rmAppIds = useMemo(() => rmRows.map((r) => r.applicationservice_id), [rmRows]);

  const isAuthed = useMemo(() => Boolean(token), [token]);
  const isAdmin = useMemo(() => roles.includes('admin'), [roles]);

  async function onLogin(e) {
    e.preventDefault();
    setError('');
    setOutput('');
    try {
      const data = await login(username, password);
      setToken(data.access_token);
      setGroups(data.groups || []);
      setRoles(data.roles || []);
      setOutput(JSON.stringify(data, null, 2));
    } catch (err) {
      setError(err.message);
    }
  }

  async function assignViewall() {
    setError('');
    try {
      await apiRequest('/role-management/global-roles/assign', {
        method: 'POST',
        token,
        body: { group: rmViewallGroup, role: 'viewall' },
      });
      await loadRoleManagement();
    } catch (err) {
      setError(err.message);
    }
  }

  async function unassignViewall(group) {
    setError('');
    try {
      await apiRequest('/role-management/global-roles/unassign', {
        method: 'POST',
        token,
        body: { group, role: 'viewall' },
      });
      await loadRoleManagement();
    } catch (err) {
      setError(err.message);
    }
  }

  async function callEndpoint(path, method) {
    setError('');
    setOutput('');
    try {
      const data = await apiRequest(path, { method, token });
      setOutput(JSON.stringify(data, null, 2));
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadAccessRequests() {
    setError('');
    try {
      const [appResp, myResp, allResp] = await Promise.all([
        apiRequest('/access-requests/applicationservices', { method: 'GET', token }),
        apiRequest('/access-requests/me', { method: 'GET', token }),
        isAdmin ? apiRequest('/access-requests/all', { method: 'GET', token }) : Promise.resolve({ requests: [] }),
      ]);
      setArRows(appResp.rows || []);
      setArMyRequests(myResp.requests || []);
      setArAllRequests(allResp.requests || []);
      if (!arAppId && (appResp.rows || []).length) setArAppId((appResp.rows || [])[0].applicationservice_id);
    } catch (err) {
      setError(err.message);
    }
  }

  async function requestAccess() {
    setError('');
    try {
      await apiRequest('/access-requests/request', {
        method: 'POST',
        token,
        body: { applicationservice_id: arAppId, role: arRole },
      });
      await loadAccessRequests();
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadRoleManagement() {
    setError('');
    try {
      const [groupsResp, rowsResp, globalRolesResp] = await Promise.all([
        apiRequest('/role-management/groups', { method: 'GET', token }),
        apiRequest('/role-management/applicationservices', { method: 'GET', token }),
        apiRequest('/role-management/global-roles', { method: 'GET', token }),
      ]);
      setRmGroups(groupsResp.groups || []);
      setRmRows(rowsResp.rows || []);
      setRmViewallAccess(globalRolesResp.viewall_access || []);
      if (!rmGroup && (groupsResp.groups || []).length) setRmGroup((groupsResp.groups || [])[0]);
      if (!rmAppId && (rowsResp.rows || []).length) setRmAppId((rowsResp.rows || [])[0].applicationservice_id);
      if (!rmViewallGroup && (groupsResp.groups || []).length) setRmViewallGroup((groupsResp.groups || [])[0]);
    } catch (err) {
      setError(err.message);
    }
  }

  async function assignRole() {
    setError('');
    try {
      await apiRequest('/role-management/assign', {
        method: 'POST',
        token,
        body: { group: rmGroup, applicationservice_id: rmAppId, role: rmRole },
      });
      await loadRoleManagement();
    } catch (err) {
      setError(err.message);
    }
  }

  async function unassignRole(group, applicationserviceId, role) {
    setError('');
    try {
      await apiRequest('/role-management/unassign', {
        method: 'POST',
        token,
        body: { group, applicationservice_id: applicationserviceId, role },
      });
      await loadRoleManagement();
    } catch (err) {
      setError(err.message);
    }
  }

  function logout() {
    setToken('');
    setGroups([]);
    setRoles([]);
    setOutput('');
    setError('');
    setTab('demo');
    setRmRows([]);
    setRmGroups([]);
    setRmGroup('');
    setArRows([]);
    setArAppId('');
    setArRole('viewer');
    setArMyRequests([]);
    setArAllRequests([]);
  }

  return (
    <div className="page">
      <div className="card">
        <div className="title">Casbin RBAC Demo (FastAPI + React)</div>
        <div className="subtitle">Users are mapped to LDAP groups; roles come from groups (password equals username)</div>

        <Section title="Login">
          <form className="row" onSubmit={onLogin}>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" />
            <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" type="password" />
            <button type="submit">Login</button>
            <button type="button" onClick={logout} disabled={!isAuthed}>Logout</button>
          </form>
          <div className="row small">
            <div><b>Token:</b> {token || '-'}</div>
            <div><b>Groups:</b> {groups.length ? groups.join(', ') : '-'}</div>
            <div><b>Roles:</b> {roles.length ? roles.join(', ') : '-'}</div>
          </div>
        </Section>

        <Section title="Tabs">
          <div className="row">
            <button type="button" disabled={!isAuthed} onClick={() => setTab('demo')}>Demo</button>
            <button
              type="button"
              disabled={!isAuthed}
              onClick={async () => {
                setTab('roles');
                if (isAuthed) await loadRoleManagement();
              }}
            >
              Role Management
            </button>
            <button
              type="button"
              disabled={!isAuthed}
              onClick={async () => {
                setTab('requests');
                if (isAuthed) await loadAccessRequests();
              }}
            >
              Access Requests
            </button>
          </div>
        </Section>

        {tab === 'demo' ? (
          <Section title="Try endpoints">
            <div className="grid">
              <button disabled={!isAuthed} onClick={() => callEndpoint('/me', 'GET')}>GET /me</button>
              <button disabled={!isAuthed} onClick={() => callEndpoint('/data', 'GET')}>GET /data</button>
              <button disabled={!isAuthed} onClick={() => callEndpoint('/data', 'POST')}>POST /data</button>
              <button disabled={!isAuthed} onClick={() => callEndpoint('/admin', 'GET')}>GET /admin</button>
              <button disabled={!isAuthed} onClick={() => callEndpoint('/applicationservices/network', 'GET')}>GET /applicationservices/network</button>
              <button disabled={!isAuthed} onClick={() => callEndpoint('/applicationservices/network', 'PUT')}>PUT /applicationservices/network</button>
              <button disabled={!isAuthed} onClick={() => callEndpoint('/applicationservices/network', 'DELETE')}>DELETE /applicationservices/network</button>
            </div>
          </Section>
        ) : null}

        {tab === 'requests' ? (
          <Section title="Access Requests">
            <div className="row">
              <button type="button" onClick={loadAccessRequests} disabled={!isAuthed}>Refresh</button>
            </div>

            <div className="row" style={{ marginTop: 10, alignItems: 'center' }}>
              <div style={{ minWidth: 180 }}><b>Request access</b></div>

              <select style={{ flex: 1 }} value={arAppId} onChange={(e) => setArAppId(e.target.value)}>
                {(arRows || []).map((r) => (
                  <option key={r.applicationservice_id} value={r.applicationservice_id}>{r.applicationservice_id}</option>
                ))}
              </select>

              <select style={{ flex: 1 }} value={arRole} onChange={(e) => setArRole(e.target.value)}>
                <option value="viewer">viewer</option>
                <option value="recertify">recertify</option>
              </select>

              <button style={{ width: 80 }} type="button" onClick={requestAccess} disabled={!arAppId}>Request</button>
            </div>

            <div style={{ overflowX: 'auto', marginTop: 12 }}>
              <div className="muted" style={{ marginBottom: 6 }}><b>My requests</b></div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Created</th>
                    <th>ApplicationService</th>
                    <th>Role</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {(arMyRequests || []).length ? (
                    arMyRequests.map((r) => (
                      <tr key={r.id}>
                        <td>{r.created_at || '-'}</td>
                        <td>{r.applicationservice_id}</td>
                        <td>{r.role}</td>
                        <td>{r.status}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="4"><span className="muted">-</span></td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {isAdmin ? (
              <div style={{ overflowX: 'auto', marginTop: 12 }}>
                <div className="muted" style={{ marginBottom: 6 }}><b>All requests (admin)</b></div>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Created</th>
                      <th>User</th>
                      <th>ApplicationService</th>
                      <th>Role</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(arAllRequests || []).length ? (
                      arAllRequests.map((r) => (
                        <tr key={r.id}>
                          <td>{r.created_at || '-'}</td>
                          <td>{r.username || '-'}</td>
                          <td>{r.applicationservice_id}</td>
                          <td>{r.role}</td>
                          <td>{r.status}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="5"><span className="muted">-</span></td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            ) : null}
          </Section>
        ) : null}

        {tab === 'roles' ? (
          <Section title="Role Management">
            {!isAdmin ? (
              <div className="muted">Only admin can manage role assignments.</div>
            ) : (
              <>
                <div className="row">
                  <button type="button" onClick={loadRoleManagement}>Refresh</button>
                </div>

                <div className="row" style={{ marginTop: 14 }}>
                  <div style={{ minWidth: 180 }}><b>grant viewall access</b></div>
                  <div className="chips" style={{ flex: 1 }}>
                    {(rmViewallAccess || []).length ? (
                      rmViewallAccess.map((g) => (
                        <span key={`viewall-${g}`} className="chip">
                          {g}
                          <button type="button" className="chipBtn" onClick={() => unassignViewall(g)}>x</button>
                        </span>
                      ))
                    ) : (
                      <span className="muted">-</span>
                    )}
                  </div>
                </div>

                <div className="row small muted" style={{ marginTop: 10 }}>
                  <div style={{ flex: 1 }}>User/group</div>
                  <div style={{ width: 60 }} />
                </div>

                <div className="row" style={{ marginTop: 4 }}>
                  <input
                    style={{ flex: 1 }}
                    value={rmViewallGroup}
                    onChange={(e) => setRmViewallGroup(e.target.value)}
                    placeholder="group"
                  />
                  <button style={{ width: 60 }} type="button" onClick={assignViewall} disabled={!rmViewallGroup}>Add</button>
                </div>

                <div className="divider" />

                <div className="row" style={{ marginTop: 6 }}>
                  <div><b>Grant applicationservice specific access</b></div>
                </div>

                <div className="row small muted" style={{ marginTop: 10 }}>
                  <div style={{ flex: 1 }}>applicationservice</div>
                  <div style={{ flex: 1 }}>role</div>
                  <div style={{ flex: 1 }}>User/group</div>
                  <div style={{ width: 60 }} />
                </div>

                <div className="row" style={{ marginTop: 4 }}>
                  <select style={{ flex: 1 }} value={rmAppId} onChange={(e) => setRmAppId(e.target.value)}>
                    {rmAppIds.map((id) => (
                      <option key={id} value={id}>{id}</option>
                    ))}
                  </select>

                  <select style={{ flex: 1 }} value={rmRole} onChange={(e) => setRmRole(e.target.value)}>
                    <option value="viewer">viewer</option>
                    <option value="recertify">recertify</option>
                  </select>

                  <input style={{ flex: 1 }} value={rmGroup} onChange={(e) => setRmGroup(e.target.value)} placeholder="group" />

                  <button style={{ width: 60 }} type="button" onClick={assignRole} disabled={!rmGroup || !rmAppId}>Add</button>
                </div>

                <div style={{ overflowX: 'auto', marginTop: 12 }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>ApplicationService</th>
                        <th>Viewer access</th>
                        <th>Recertify access</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rmRows.map((row) => (
                        <tr key={row.applicationservice_id}>
                          <td>{row.applicationservice_id}</td>
                          <td>
                            {(row.viewer_access || []).length ? (
                              <div className="chips">
                                {row.viewer_access.map((g) => (
                                  <span key={`${row.applicationservice_id}-viewer-${g}`} className="chip">
                                    {g}
                                    <button
                                      type="button"
                                      className="chipBtn"
                                      onClick={() => unassignRole(g, row.applicationservice_id, 'viewer')}
                                    >
                                      x
                                    </button>
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="muted">-</span>
                            )}
                          </td>
                          <td>
                            {(row.recertify_access || []).length ? (
                              <div className="chips">
                                {row.recertify_access.map((g) => (
                                  <span key={`${row.applicationservice_id}-recertify-${g}`} className="chip">
                                    {g}
                                    <button
                                      type="button"
                                      className="chipBtn"
                                      onClick={() => unassignRole(g, row.applicationservice_id, 'recertify')}
                                    >
                                      x
                                    </button>
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="muted">-</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </Section>
        ) : null}

        <Section title="Result">
          {error ? <pre className="error">{error}</pre> : null}
          {output ? <pre className="output">{output}</pre> : <div className="muted">No output yet.</div>}
        </Section>
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
