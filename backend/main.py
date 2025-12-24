from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import casbin
from casbin.persist.adapters import FileAdapter
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import yaml

from backend.routers.access_requests import create_access_requests_router
from backend.routers.role_management import create_role_management_router


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    groups: list[str]
    roles: list[str]


USERS: dict[str, dict[str, object]] = {
    "alice": {"password": "alice"},
    "bob": {"password": "bob"},
    "eve": {"password": "eve"},
    "carol": {"password": "carol"},
}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text())
    return data or {}


def _load_user_ldap_groups(base_dir: Path) -> dict[str, set[str]]:
    raw = _load_yaml(base_dir / "userid_to_group_mapping.yaml")
    return {str(user): set(map(str, groups or [])) for user, groups in raw.items()}


def _load_group_global_roles(base_dir: Path) -> dict[str, set[str]]:
    raw = _load_yaml(base_dir / "roles_4_groups2global.yaml")
    return {str(group): set(map(str, roles or [])) for group, roles in raw.items()}


def _load_user_global_roles(base_dir: Path) -> dict[str, set[str]]:
    raw = _load_yaml(base_dir / "roles_4_users2global.yaml")
    return {str(user): set(map(str, roles or [])) for user, roles in raw.items()}


def _load_group_doc_roles(base_dir: Path) -> dict[str, dict[str, set[str]]]:
    raw = _load_yaml(base_dir / "roles_4_group2applicationservice.yaml")
    out: dict[str, dict[str, set[str]]] = {}
    for group, doc_map in raw.items():
        group_s = str(group)
        out[group_s] = {}
        if not doc_map:
            continue
        for doc_id, roles in doc_map.items():
            out[group_s][str(doc_id)] = set(map(str, roles or []))
    return out


def _load_applicationservices(base_dir: Path) -> dict[str, dict[str, str]]:
    raw = _load_yaml(base_dir / "applicationservices.yaml")
    items = raw.get("applicationservices") or []
    out: dict[str, dict[str, str]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        app_id = item.get("id")
        if app_id is None:
            continue
        app_id_s = str(app_id)
        content = item.get("content")
        out[app_id_s] = {"content": str(content) if content is not None else f"ApplicationService {app_id_s}"}
    return out


BASE_DIR = Path(__file__).parent
USER_LDAP_GROUPS = _load_user_ldap_groups(BASE_DIR)
LDAP_GROUP_GLOBAL_ROLES = _load_group_global_roles(BASE_DIR)
LDAP_USER_GLOBAL_ROLES = _load_user_global_roles(BASE_DIR)
LDAP_GROUP_DOC_ROLES = _load_group_doc_roles(BASE_DIR)

GROUP_DOC_ROLES_PATH = BASE_DIR / "roles_4_group2applicationservice.yaml"
GROUP_GLOBAL_ROLES_PATH = BASE_DIR / "roles_4_groups2global.yaml"

ACCESS_REQUESTS_PATH = BASE_DIR / "access_requests.yaml"

APPLICATIONSERVICES = _load_applicationservices(BASE_DIR)


def build_enforcer() -> casbin.Enforcer:
    base_dir = Path(__file__).parent
    model_path = base_dir / "casbin_model.conf"
    policy_path = base_dir / "casbin_policy.csv"

    adapter = FileAdapter(str(policy_path))
    e = casbin.Enforcer(str(model_path), adapter)
    e.load_policy()
    return e


ENFORCER = build_enforcer()

app = FastAPI(title="Casbin RBAC Demo")

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _parse_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "bearer "
    if authorization.lower().startswith(prefix):
        return authorization[len(prefix) :].strip()
    return None


def authenticate_token(token: str) -> dict[str, Any]:
    user = USERS.get(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    groups = set(USER_LDAP_GROUPS.get(token, set()))

    global_roles: set[str] = set()
    for g in groups:
        global_roles |= set(LDAP_GROUP_GLOBAL_ROLES.get(g, set()))

    global_roles |= set(LDAP_USER_GLOBAL_ROLES.get(token, set()))

    applicationservice_roles_acc: dict[str, set[str]] = {}
    for g in groups:
        for applicationservice_id, roles_for_appsvc in LDAP_GROUP_DOC_ROLES.get(g, {}).items():
            applicationservice_roles_acc.setdefault(applicationservice_id, set()).update(roles_for_appsvc)

    roles = sorted(list(global_roles | {"user"}))
    applicationservice_roles = {
        applicationservice_id: sorted(list(r)) for applicationservice_id, r in applicationservice_roles_acc.items()
    }

    return {
        "username": token,
        "groups": sorted(list(groups)),
        "roles": roles,
        "applicationservice_roles": applicationservice_roles,
    }


CurrentUser = Annotated[dict[str, Any], Depends(lambda authorization=Header(default=None): authenticate_token(_parse_bearer(authorization) or ""))]


def enforce(
    user: dict[str, Any], obj: str, act: str, applicationservice: dict[str, Any] | None = None
) -> None:
    applicationservice_ctx = applicationservice or {"id": ""}
    ENFORCER.load_policy()
    allowed = ENFORCER.enforce(user, obj, act, applicationservice_ctx)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "Forbidden by RBAC", "roles": user.get("roles", []), "obj": obj, "act": act},
        )


app.include_router(
    create_role_management_router(
        enforce=lambda user, obj, act: enforce(user, obj, act),
        get_current_user=lambda authorization=Header(default=None): authenticate_token(
            _parse_bearer(authorization) or ""
        ),
        group_doc_roles_path=GROUP_DOC_ROLES_PATH,
        group_global_roles_path=GROUP_GLOBAL_ROLES_PATH,
        user_ldap_groups=USER_LDAP_GROUPS,
        ldap_group_global_roles=LDAP_GROUP_GLOBAL_ROLES,
        ldap_group_doc_roles=LDAP_GROUP_DOC_ROLES,
        applicationservices=APPLICATIONSERVICES,
    )
)

app.include_router(
    create_access_requests_router(
        enforce=lambda user, obj, act: enforce(user, obj, act),
        get_current_user=lambda authorization=Header(default=None): authenticate_token(
            _parse_bearer(authorization) or ""
        ),
        access_requests_path=ACCESS_REQUESTS_PATH,
        applicationservices=APPLICATIONSERVICES,
    )
)


@app.get("/")
def home() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    user = USERS.get(payload.username)
    if not user or user["password"] != payload.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username/password")

    ctx = authenticate_token(payload.username)
    return LoginResponse(access_token=payload.username, groups=ctx["groups"], roles=ctx["roles"])


@app.get("/me")
def me(user: CurrentUser) -> dict[str, Any]:
    return user


@app.get("/data")
def read_data(user: CurrentUser) -> dict[str, Any]:
    enforce(user, "/data", "GET")
    return {"message": "You can read data", "user": user}


@app.post("/data")
def write_data(user: CurrentUser) -> dict[str, Any]:
    enforce(user, "/data", "POST")
    return {"message": "You can write data", "user": user}


@app.get("/admin")
def admin(user: CurrentUser) -> dict[str, Any]:
    enforce(user, "/admin", "GET")
    return {"message": "Welcome to admin", "user": user}


@app.get("/applicationservices/{applicationservice_id}")
def get_applicationservice(applicationservice_id: str, user: CurrentUser) -> dict[str, Any]:
    enforce(
        user,
        f"/applicationservices/{applicationservice_id}",
        "GET",
        applicationservice={"id": applicationservice_id},
    )
    applicationservice = APPLICATIONSERVICES.get(applicationservice_id)
    if not applicationservice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
    return {"applicationservice_id": applicationservice_id, "content": applicationservice["content"], "user": user}


@app.put("/applicationservices/{applicationservice_id}")
def update_applicationservice(applicationservice_id: str, user: CurrentUser) -> dict[str, Any]:
    enforce(
        user,
        f"/applicationservices/{applicationservice_id}",
        "PUT",
        applicationservice={"id": applicationservice_id},
    )
    if applicationservice_id not in APPLICATIONSERVICES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
    return {"applicationservice_id": applicationservice_id, "message": "Updated", "user": user}


@app.delete("/applicationservices/{applicationservice_id}")
def delete_applicationservice(applicationservice_id: str, user: CurrentUser) -> dict[str, Any]:
    enforce(
        user,
        f"/applicationservices/{applicationservice_id}",
        "DELETE",
        applicationservice={"id": applicationservice_id},
    )
    if applicationservice_id not in APPLICATIONSERVICES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
    return {"applicationservice_id": applicationservice_id, "message": "Deleted", "user": user}
