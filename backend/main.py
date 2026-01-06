from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import yaml

from backend.config_loader import (
    load_applicationservices,
    load_roles_4_group2applicationservice,
    load_roles_4_groups2global,
    load_roles_4_users2global,
    load_userid_to_group_mapping,
)
from backend.casbin_service import build_enforcer, enforce_rbac
from backend.routers.access_requests import create_access_requests_router
from backend.routers.apps import create_apps_router
from backend.routers.role_management import create_role_management_router
from backend.routers.user_groups import create_user_groups_router


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

USERID_TO_GROUP_MAPPING_PATH = BASE_DIR / "userid_to_group_mapping.yaml"

GROUP_DOC_ROLES_PATH = BASE_DIR / "roles_4_group2applicationservice.yaml"
GROUP_GLOBAL_ROLES_PATH = BASE_DIR / "roles_4_groups2global.yaml"

ACCESS_REQUESTS_PATH = BASE_DIR / "access_requests.yaml"

APPLICATIONSERVICES = load_applicationservices(BASE_DIR)

APP_FLOWS: dict[str, list[dict[str, Any]]] = {}


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

    # the keys in the dictionary below are referred to in casbin_model.conf
    return {
        "username": user_id,
        "groups": sorted(list(groups)),
        "roles": roles,
        "applicationservice_roles": applicationservice_roles,
    }


def get_current_user_context(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user_id = _parse_bearer(authorization)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    return get_user_context(user_id)


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user_context)]


def enforce_request(
    usercontext: dict[str, Any], obj: str, act: str, applicationservice: dict[str, Any] | None = None
) -> None:
    enforce_rbac(enforcer=ENFORCER, usercontext=usercontext, obj=obj, act=act, applicationservice=applicationservice)


app.include_router(
    create_role_management_router(
        enforce=lambda usercontext, obj, act: enforce_request(usercontext, obj, act),
        get_current_user_context=get_current_user_context,
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
        enforce=lambda usercontext, obj, act: enforce_request(usercontext, obj, act),
        get_current_user_context=get_current_user_context,
        access_requests_path=ACCESS_REQUESTS_PATH,
        applicationservices=APPLICATIONSERVICES,
    )
)

app.include_router(
    create_apps_router(
        enforce=lambda usercontext, obj, act, applicationservice: enforce_request(
            usercontext, obj, act, applicationservice=applicationservice
        ),
        get_current_user_context=get_current_user_context,
        applicationservices=APPLICATIONSERVICES,
        app_flows=APP_FLOWS,
    )
)

app.include_router(
    create_user_groups_router(
        enforce=lambda usercontext, obj, act: enforce_request(usercontext, obj, act),
        get_current_user_context=get_current_user_context,
        user_ldap_groups=USER_LDAP_GROUPS,
        userid_to_group_mapping_path=USERID_TO_GROUP_MAPPING_PATH,
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
