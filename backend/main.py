from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.config_loader import (
    load_applicationservices,
    load_roles_4_group2applicationservice,
    load_roles_4_groups2global,
    load_roles_4_users2global,
    load_userid_to_group_mapping,
)
from backend.casbin_service import build_enforcer, enforce
from backend.routers.access_requests import create_access_requests_router
from backend.routers.role_management import create_role_management_router


class LoginRequest(BaseModel):
    username: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    groups: list[str]
    roles: list[str]


USERS: set[str] = {"alice", "bob", "eve", "carol"}


BASE_DIR = Path(__file__).parent
USER_LDAP_GROUPS = load_userid_to_group_mapping(BASE_DIR)
roles4groups2global = load_roles_4_groups2global(BASE_DIR)
LDAP_USER_GLOBAL_ROLES = load_roles_4_users2global(BASE_DIR)
group2appsvc_roles = load_roles_4_group2applicationservice(BASE_DIR)

GROUP_DOC_ROLES_PATH = BASE_DIR / "roles_4_group2applicationservice.yaml"
GROUP_GLOBAL_ROLES_PATH = BASE_DIR / "roles_4_groups2global.yaml"

ACCESS_REQUESTS_PATH = BASE_DIR / "access_requests.yaml"

APPLICATIONSERVICES = load_applicationservices(BASE_DIR)


ENFORCER = build_enforcer(
    model_path=BASE_DIR / "casbin_model.conf",
    policy_path=BASE_DIR / "casbin_policy.csv",
)

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


def get_user_context(user_id: str) -> dict[str, Any]:
    if user_id not in USERS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")

    groups = set(USER_LDAP_GROUPS.get(user_id, set()))

    global_roles: set[str] = set()
    for g in groups:
        global_roles |= set(roles4groups2global.get(g, set()))

    global_roles |= set(LDAP_USER_GLOBAL_ROLES.get(user_id, set()))

    applicationservice_roles_acc: dict[str, set[str]] = {}
    for g in groups:
        for applicationservice_id, roles_for_appsvc in group2appsvc_roles.get(g, {}).items():
            applicationservice_roles_acc.setdefault(applicationservice_id, set()).update(roles_for_appsvc)

    roles = sorted(list(global_roles | {"user"}))
    applicationservice_roles = {
        applicationservice_id: sorted(list(r)) for applicationservice_id, r in applicationservice_roles_acc.items()
    }

    return {
        "username": user_id,
        "groups": sorted(list(groups)),
        "roles": roles,
        "applicationservice_roles": applicationservice_roles,
    }


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user_id = _parse_bearer(authorization)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    return get_user_context(user_id)


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]


def enforce_request(
    user: dict[str, Any], obj: str, act: str, applicationservice: dict[str, Any] | None = None
) -> None:
    enforce(enforcer=ENFORCER, user=user, obj=obj, act=act, applicationservice=applicationservice)


app.include_router(
    create_role_management_router(
        enforce=lambda user, obj, act: enforce_request(user, obj, act),
        get_current_user=get_current_user,
        group_doc_roles_path=GROUP_DOC_ROLES_PATH,
        group_global_roles_path=GROUP_GLOBAL_ROLES_PATH,
        user_ldap_groups=USER_LDAP_GROUPS,
        roles4groups2global=roles4groups2global,
        group2appsvc_roles=group2appsvc_roles,
        applicationservices=APPLICATIONSERVICES,
    )
)

app.include_router(
    create_access_requests_router(
        enforce=lambda user, obj, act: enforce_request(user, obj, act),
        get_current_user=get_current_user,
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
    ctx = get_user_context(payload.username)
    return LoginResponse(access_token=payload.username, groups=ctx["groups"], roles=ctx["roles"])


@app.get("/me")
def me(user: CurrentUser) -> dict[str, Any]:
    return user


@app.get("/data")
def read_data(user: CurrentUser) -> dict[str, Any]:
    enforce_request(user, "/data", "GET")
    return {"message": "You can read data", "user": user}


@app.post("/data")
def write_data(user: CurrentUser) -> dict[str, Any]:
    enforce_request(user, "/data", "POST")
    return {"message": "You can write data", "user": user}


@app.get("/admin")
def admin(user: CurrentUser) -> dict[str, Any]:
    enforce_request(user, "/admin", "GET")
    return {"message": "Welcome to admin", "user": user}


@app.get("/apps/{applicationservice_id}")
def get_applicationservice(applicationservice_id: str, user: CurrentUser) -> dict[str, Any]:
    enforce_request(
        user,
        f"/apps/{applicationservice_id}",
        "GET",
        applicationservice={"id": applicationservice_id},
    )
    applicationservice = APPLICATIONSERVICES.get(applicationservice_id)
    if not applicationservice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
    return {"applicationservice_id": applicationservice_id, "content": applicationservice["content"], "user": user}


@app.put("/apps/{applicationservice_id}")
def update_applicationservice(applicationservice_id: str, user: CurrentUser) -> dict[str, Any]:
    enforce_request(
        user,
        f"/apps/{applicationservice_id}",
        "PUT",
        applicationservice={"id": applicationservice_id},
    )
    if applicationservice_id not in APPLICATIONSERVICES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
    return {"applicationservice_id": applicationservice_id, "message": "Updated", "user": user}


@app.delete("/apps/{applicationservice_id}")
def delete_applicationservice(applicationservice_id: str, user: CurrentUser) -> dict[str, Any]:
    enforce_request(
        user,
        f"/apps/{applicationservice_id}",
        "DELETE",
        applicationservice={"id": applicationservice_id},
    )
    if applicationservice_id not in APPLICATIONSERVICES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
    return {"applicationservice_id": applicationservice_id, "message": "Deleted", "user": user}
