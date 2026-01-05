from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel


class RoleAssignmentRequest(BaseModel):
    group: str
    appsvc_id: str
    role: str


class GlobalRoleAssignmentRequest(BaseModel):
    group: str
    role: str


def create_role_management_router(
    *,
    enforce: Callable[[dict[str, Any], str, str], None],
    get_current_user: Callable[..., dict[str, Any]],
    group_doc_roles_path: Path,
    group_global_roles_path: Path,
    user_ldap_groups: dict[str, set[str]],
    roles4groups2global: dict[str, set[str]],
    group2appsvc_roles: dict[str, dict[str, set[str]]],
    applicationservices: dict[str, dict[str, str]],
) -> APIRouter:
    router = APIRouter()

    def _write_group_doc_roles_yaml() -> None:
        out: dict[str, dict[str, list[str]]] = {}
        for group, app_map in group2appsvc_roles.items():
            out[group] = {}
            for applicationservice_id, roles in app_map.items():
                out[group][str(applicationservice_id)] = sorted(list(roles))
        group_doc_roles_path.write_text(yaml.safe_dump(out, sort_keys=True))

    def _write_group_global_roles_yaml() -> None:
        out: dict[str, list[str]] = {}
        for group, roles in roles4groups2global.items():
            if not roles:
                continue
            out[group] = sorted(list(roles))
        group_global_roles_path.write_text(yaml.safe_dump(out, sort_keys=True))

    def _all_known_groups() -> list[str]:
        groups: set[str] = set()
        for gs in user_ldap_groups.values():
            groups |= set(gs)
        groups |= set(roles4groups2global.keys())
        groups |= set(group2appsvc_roles.keys())
        return sorted(list(groups))

    @router.get("/role-management/groups")
    def list_groups(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/role-management/groups", "GET")
        return {"groups": _all_known_groups()}

    @router.get("/role-management/applicationservices")
    def list_applicationservice_roles(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/role-management/applicationservices", "GET")

        viewer_groups_by_app: dict[str, list[str]] = {}
        recertify_groups_by_app: dict[str, list[str]] = {}

        for group, app_map in group2appsvc_roles.items():
            for applicationservice_id, roles in app_map.items():
                app_id = str(applicationservice_id)
                if "viewer" in roles:
                    viewer_groups_by_app.setdefault(app_id, []).append(group)
                if "recertify" in roles:
                    recertify_groups_by_app.setdefault(app_id, []).append(group)

        rows: list[dict[str, Any]] = []
        for applicationservice_id in sorted(list(applicationservices.keys())):
            rows.append(
                {
                    "appsvc_id": applicationservice_id,
                    "viewer_access": sorted(viewer_groups_by_app.get(applicationservice_id, [])),
                    "recertify_access": sorted(recertify_groups_by_app.get(applicationservice_id, [])),
                }
            )

        return {"rows": rows}

    @router.get("/role-management/global-roles")
    def list_global_roles(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/role-management/global-roles", "GET")
        viewall_groups = sorted([g for g, roles in roles4groups2global.items() if "viewall" in roles])
        return {"viewall_access": viewall_groups}

    @router.post("/role-management/global-roles/assign")
    def assign_global_role(
        payload: GlobalRoleAssignmentRequest, user: dict[str, Any] = Depends(get_current_user)
    ) -> dict[str, Any]:
        enforce(user, "/role-management/global-roles/assign", "POST")
        role = payload.role.strip()
        if role not in {"viewall"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

        roles4groups2global.setdefault(payload.group, set()).add(role)
        _write_group_global_roles_yaml()
        return {"status": "ok"}

    @router.post("/role-management/global-roles/unassign")
    def unassign_global_role(
        payload: GlobalRoleAssignmentRequest, user: dict[str, Any] = Depends(get_current_user)
    ) -> dict[str, Any]:
        enforce(user, "/role-management/global-roles/unassign", "POST")
        role = payload.role.strip()
        if role not in {"viewall"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

        roles = roles4groups2global.get(payload.group)
        if not roles:
            return {"status": "ok"}
        roles.discard(role)
        if not roles:
            roles4groups2global.pop(payload.group, None)
        _write_group_global_roles_yaml()
        return {"status": "ok"}

    @router.post("/role-management/assign")
    def assign_role(payload: RoleAssignmentRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/role-management/assign", "POST")

        role = payload.role.strip()
        if role not in {"viewer", "recertify"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")
        if payload.appsvc_id not in applicationservices:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")

        group2appsvc_roles.setdefault(payload.group, {})
        group2appsvc_roles[payload.group].setdefault(payload.appsvc_id, set()).add(role)
        _write_group_doc_roles_yaml()
        return {"status": "ok"}

    @router.post("/role-management/unassign")
    def unassign_role(payload: RoleAssignmentRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/role-management/unassign", "POST")

        role = payload.role.strip()
        if role not in {"viewer", "recertify"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

        app_map = group2appsvc_roles.get(payload.group)
        if not app_map:
            return {"status": "ok"}
        roles = app_map.get(payload.appsvc_id)
        if not roles:
            return {"status": "ok"}
        roles.discard(role)
        if not roles:
            app_map.pop(payload.appsvc_id, None)
        if not app_map:
            group2appsvc_roles.pop(payload.group, None)

        _write_group_doc_roles_yaml()
        return {"status": "ok"}

    return router
