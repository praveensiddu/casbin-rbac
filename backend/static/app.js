const { useMemo, useState } = React;

async function login(username) {
  const res = await fetch(`${window.API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
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
  const [token, setToken] = useState('');
  const [groups, setGroups] = useState([]);
  const [roles, setRoles] = useState([]);
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [tab, setTab] = useState('apps');

  const userIds = useMemo(() => ['alice', 'bob', 'eve', 'carol'], []);
  const [selectedUserId, setSelectedUserId] = useState('alice');

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
  const [arGroup, setArGroup] = useState('');
  const [arMyRequests, setArMyRequests] = useState([]);
  const [arAllRequests, setArAllRequests] = useState([]);

  const [appsRows, setAppsRows] = useState([]);
  const [selectedAppId, setSelectedAppId] = useState('');
  const [appsView, setAppsView] = useState('apps');
  const [flowsRows, setFlowsRows] = useState([]);
  const [flowName, setFlowName] = useState('');

  const [ugRows, setUgRows] = useState([]);
  const [ugNewUserId, setUgNewUserId] = useState('');
  const [ugNewGroup, setUgNewGroup] = useState('');

  const rmAppIds = useMemo(() => rmRows.map((r) => r.appsvc_id), [rmRows]);

  const isAuthed = useMemo(() => Boolean(token), [token]);
  const isAdmin = useMemo(() => roles.includes('admin'), [roles]);

  async function onLogin() {
    setError('');
    setOutput('');
    try {
      const data = await login(selectedUserId);
      setToken(data.access_token);
      setGroups(data.groups || []);
      setRoles(data.roles || []);
      setOutput(JSON.stringify(data, null, 2));

      try {
        const appsResp = await apiRequest('/apps', { method: 'GET', token: data.access_token });
        setAppsRows(appsResp.rows || []);
        if ((appsResp.rows || []).length) setSelectedAppId((appsResp.rows || [])[0].applicationservice_id);
        setAppsView('apps');
        setTab('apps');
      } catch {
        // ignore auto-load errors (user can click Refresh)
      }
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadApps() {
    setError('');
    try {
      const resp = await apiRequest('/apps', { method: 'GET', token });
      setAppsRows(resp.rows || []);
      if (!selectedAppId && (resp.rows || []).length) setSelectedAppId((resp.rows || [])[0].applicationservice_id);
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadFlows(appId) {
    setError('');
    try {
      const resp = await apiRequest(`/apps/${appId}/flows`, { method: 'GET', token });
      setFlowsRows(resp.rows || []);
    } catch (err) {
      setError(err.message);
    }
  }

  async function addFlow() {
    setError('');
    try {
      await apiRequest(`/apps/${selectedAppId}/flows`, {
        method: 'POST',
        token,
        body: { name: flowName },
      });
      setFlowName('');
      await loadFlows(selectedAppId);
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadUserGroups() {
    setError('');
    try {
      const resp = await apiRequest('/user-groups', { method: 'GET', token });
      setUgRows(resp.rows || []);
    } catch (err) {
      setError(err.message);
    }
  }

  async function addUserGroup() {
    setError('');
    try {
      await apiRequest('/user-groups/add', {
        method: 'POST',
        token,
        body: { user_id: ugNewUserId, group: ugNewGroup },
      });
      setUgNewGroup('');
      await loadUserGroups();
    } catch (err) {
      setError(err.message);
    }
  }

  async function removeUserGroup(userId, group) {
    setError('');
    try {
      await apiRequest('/user-groups/remove', {
        method: 'POST',
        token,
        body: { user_id: userId, group },
      });
      await loadUserGroups();
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
        body: { applicationservice_id: arAppId, role: arRole, group: arGroup },
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
      if (!rmAppId && (rowsResp.rows || []).length) setRmAppId((rowsResp.rows || [])[0].appsvc_id);
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
        body: { group: rmGroup, appsvc_id: rmAppId, role: rmRole },
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
        body: { group, appsvc_id: applicationserviceId, role },
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
    setTab('apps');
    setSelectedUserId('alice');
    setRmRows([]);
    setRmGroups([]);
    setRmGroup('');
    setArRows([]);
    setArAppId('');
    setArRole('viewer');
    setArGroup('');
    setArMyRequests([]);
    setArAllRequests([]);
    setAppsRows([]);
    setSelectedAppId('');
    setAppsView('apps');
    setFlowsRows([]);
    setFlowName('');

    setUgRows([]);
    setUgNewUserId('');
    setUgNewGroup('');
  }

  return (
    <div className="page">
      <div className="card">
        <div className="title">Casbin RBAC Demo (FastAPI + React)</div>
        <div className="subtitle">Users are mapped to LDAP groups; roles come from groups (demo login is a userId selector)</div>

        <Section title="Login">
          <div className="row">
            <select value={selectedUserId} onChange={(e) => setSelectedUserId(e.target.value)} disabled={isAuthed}>
              {userIds.map((u) => (
                <option key={u} value={u}>{u}</option>
              ))}
            </select>
            <button type="button" onClick={onLogin} disabled={isAuthed}>Login</button>
            <button type="button" onClick={logout} disabled={!isAuthed}>Logout</button>
          </div>
          <div className="row small">
            <div><b>Token:</b> {token || '-'}</div>
            <div><b>Groups:</b> {groups.length ? groups.join(', ') : '-'}</div>
            <div><b>Roles:</b> {roles.length ? roles.join(', ') : '-'}</div>
          </div>
        </Section>

        <div className="tabs">
          <button
            type="button"
            className={`tab ${tab === 'apps' ? 'active' : ''}`}
            disabled={!isAuthed}
            onClick={async () => {
              setTab('apps');
              if (isAuthed) await loadApps();
            }}
          >
            Apps
          </button>
          <button
            type="button"
            className={`tab ${tab === 'roles' ? 'active' : ''}`}
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
            className={`tab ${tab === 'usergroups' ? 'active' : ''}`}
            disabled={!isAuthed}
            onClick={async () => {
              setTab('usergroups');
              if (isAuthed) await loadUserGroups();
            }}
          >
            User Groups
          </button>
          <button
            type="button"
            className={`tab ${tab === 'requests' ? 'active' : ''}`}
            disabled={!isAuthed}
            onClick={async () => {
              setTab('requests');
              if (isAuthed) await loadAccessRequests();
            }}
          >
            Access Requests
          </button>
          <button
            type="button"
            className={`tab ${tab === 'demo' ? 'active' : ''}`}
            disabled={!isAuthed}
            onClick={() => setTab('demo')}
          >
            Demo
          </button>
        </div>

        {tab === 'apps' ? (
          <Section title="Apps">
            {appsView === 'apps' ? (
              <>
                <div className="row">
                  <button type="button" onClick={loadApps} disabled={!isAuthed}>Refresh</button>
                  <button
                    type="button"
                    disabled={!isAuthed || !selectedAppId}
                    onClick={async () => {
                      await loadFlows(selectedAppId);
                      setAppsView('flows');
                    }}
                  >
                    Flows Mgmt
                  </button>
                </div>

                <div className="row small muted" style={{ marginTop: 10 }}>
                  <div style={{ width: 36 }} />
                  <div style={{ flex: 1 }}>App</div>
                  <div style={{ flex: 3 }}>Content</div>
                </div>

                <div style={{ overflowX: 'auto', marginTop: 8 }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th style={{ width: 36 }} />
                        <th>App</th>
                        <th>Content</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(appsRows || []).length ? (
                        appsRows.map((r) => (
                          <tr key={r.applicationservice_id}>
                            <td>
                              <input
                                type="radio"
                                name="selectedApp"
                                checked={selectedAppId === r.applicationservice_id}
                                onChange={() => setSelectedAppId(r.applicationservice_id)}
                              />
                            </td>
                            <td>{r.applicationservice_id}</td>
                            <td>{r.content || ''}</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="3"><span className="muted">-</span></td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <>
                <div className="row">
                  <button type="button" onClick={() => setAppsView('apps')}>Back to apps</button>
                  <button
                    type="button"
                    disabled={!isAuthed || !selectedAppId}
                    onClick={() => loadFlows(selectedAppId)}
                  >
                    Refresh
                  </button>
                  <div className="muted"><b>App:</b> {selectedAppId || '-'}</div>
                </div>

                <div className="row" style={{ marginTop: 10, alignItems: 'center' }}>
                  <div style={{ minWidth: 120 }}><b>Add Flow</b></div>
                  <input
                    style={{ flex: 1, minWidth: 220 }}
                    value={flowName}
                    onChange={(e) => setFlowName(e.target.value)}
                    placeholder="flowname"
                  />
                  <button
                    style={{ width: 80 }}
                    type="button"
                    disabled={!isAuthed || !selectedAppId || !flowName.trim()}
                    onClick={addFlow}
                  >
                    Add
                  </button>
                </div>

                <div style={{ overflowX: 'auto', marginTop: 12 }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Flow</th>
                        <th>Content</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(flowsRows || []).length ? (
                        flowsRows.map((f) => (
                          <tr key={f.id || f.name}>
                            <td>{f.name || '-'}</td>
                            <td>{f.content || ''}</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="2"><span className="muted">-</span></td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </Section>
        ) : null}

        {tab === 'usergroups' ? (
          <Section title="User -> Groups">
            <div className="row">
              <button type="button" onClick={loadUserGroups} disabled={!isAuthed}>Refresh</button>
            </div>

            <div className="row small muted" style={{ marginTop: 10 }}>
              <div style={{ flex: 1 }}>userId</div>
              <div style={{ flex: 2 }}>group</div>
              <div style={{ width: 80 }} />
            </div>

            <div className="row" style={{ marginTop: 4 }}>
              <input
                style={{ flex: 1 }}
                value={ugNewUserId}
                onChange={(e) => setUgNewUserId(e.target.value)}
                placeholder="userId"
              />
              <input
                style={{ flex: 2 }}
                value={ugNewGroup}
                onChange={(e) => setUgNewGroup(e.target.value)}
                placeholder="group"
              />
              <button
                style={{ width: 80 }}
                type="button"
                onClick={addUserGroup}
                disabled={!ugNewUserId.trim() || !ugNewGroup.trim()}
              >
                Add
              </button>
            </div>

            <div style={{ overflowX: 'auto', marginTop: 12 }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Groups</th>
                  </tr>
                </thead>
                <tbody>
                  {(ugRows || []).length ? (
                    ugRows.map((r) => (
                      <tr key={r.user_id}>
                        <td>{r.user_id}</td>
                        <td>
                          {(r.groups || []).length ? (
                            <div className="chips">
                              {r.groups.map((g) => (
                                <span key={`${r.user_id}-${g}`} className="chip">
                                  {g}
                                  <button type="button" className="chipBtn" onClick={() => removeUserGroup(r.user_id, g)}>x</button>
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="muted">-</span>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="2"><span className="muted">-</span></td>
                    </tr>
                  )}
                </tbody>
              </table>
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

              <input
                style={{ flex: 1, minWidth: 220 }}
                value={arGroup}
                onChange={(e) => setArGroup(e.target.value)}
                placeholder="group"
              />

              <button style={{ width: 80 }} type="button" onClick={requestAccess} disabled={!arAppId}>Request</button>
            </div>

            <div style={{ overflowX: 'auto', marginTop: 12 }}>
              <div className="muted" style={{ marginBottom: 6 }}><b>My requests</b></div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Created</th>
                    <th>Group</th>
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
                        <td>{r.group || '-'}</td>
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

            {isAdmin ? (
              <div style={{ overflowX: 'auto', marginTop: 12 }}>
                <div className="muted" style={{ marginBottom: 6 }}><b>All requests (admin)</b></div>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Created</th>
                      <th>User</th>
                      <th>Group</th>
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
                          <td>{r.requested_by || r.username || '-'}</td>
                          <td>{r.group || '-'}</td>
                          <td>{r.applicationservice_id}</td>
                          <td>{r.role}</td>
                          <td>{r.status}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="6"><span className="muted">-</span></td>
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
                        <tr key={row.appsvc_id}>
                          <td>{row.appsvc_id}</td>
                          <td>
                            {(row.viewer_access || []).length ? (
                              <div className="chips">
                                {row.viewer_access.map((g) => (
                                  <span key={`${row.appsvc_id}-viewer-${g}`} className="chip">
                                    {g}
                                    <button
                                      type="button"
                                      className="chipBtn"
                                      onClick={() => unassignRole(g, row.appsvc_id, 'viewer')}
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
                                  <span key={`${row.appsvc_id}-recertify-${g}`} className="chip">
                                    {g}
                                    <button
                                      type="button"
                                      className="chipBtn"
                                      onClick={() => unassignRole(g, row.appsvc_id, 'recertify')}
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
