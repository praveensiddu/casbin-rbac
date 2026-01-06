# Casbin RBAC Demo (FastAPI + React)

## Backend (FastAPI)

### Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

### Users

- alice / alice -> admin (via groups / user-global roles)
- bob / bob -> viewer + recertify for a subset of applicationservices (via groups)
- eve / eve -> viewer for a subset of applicationservices (via groups)
- carol / carol -> viewall

Auth is a demo token: the returned `access_token` is just the username.

## Frontend (React)

The React UI is served by the FastAPI server (no Node.js, no npm).

Open `http://127.0.0.1:8000/`.

## RBAC Rules

The backend uses a Casbin RBAC model with `keyMatch` + `regexMatch`.

- Model: `backend/casbin_model.conf`
- Policy: `backend/casbin_policy.csv`

## ABAC: subset of applicationservices

For `/apps/{applicationservice_id}` the backend also uses ABAC:

- `viewer` and `recertify` are applicationservice-scoped roles: access is granted only if the user has that role for the specific `applicationservice_id`.
- `viewall` is a global role that grants view access (GET) to all applicationservices.
- This is controlled in code via LDAP-group mappings in `backend/main.py`:
  - `USER_LDAP_GROUPS` (user -> groups)
  - `LDAP_GROUP_GLOBAL_ROLES` (group -> global roles)
  - `LDAP_USER_GLOBAL_ROLES` (user -> global roles)
  - `LDAP_GROUP_DOC_ROLES` (group -> per-applicationservice roles)

These role mappings are loaded from YAML files:

- `backend/user_ldap_groups.yaml`
- `backend/group_global_roles.yaml`
- `backend/user_global_roles.yaml`
- `backend/group_doc_roles.yaml`

ApplicationServices are loaded from:

- `backend/applicationservices.yaml`

- `admin` can GET/PUT/DELETE `/apps/*`
- `viewall` can GET `/apps/*`
- `recertify` can GET/PUT `/apps/*` (only for applicationservices where they have recertify)
- `viewer` can GET `/apps/*` (only for applicationservices where they have viewer)
