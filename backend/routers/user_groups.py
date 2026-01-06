from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel


class UserGroupAdd(BaseModel):
    user_id: str
    group: str


class UserGroupRemove(BaseModel):
    user_id: str
    group: str


def create_user_groups_router(
    *,
    enforce: Callable[[dict[str, Any], str, str], None],
    get_current_user_context: Callable[..., dict[str, Any]],
    user_ldap_groups: dict[str, set[str]],
    userid_to_group_mapping_path: Path,
) -> APIRouter:
    router = APIRouter()

    def _write_userid_to_group_mapping() -> None:
        payload: dict[str, list[str]] = {
            user_id: sorted(list(groups)) for user_id, groups in user_ldap_groups.items()
        }
        userid_to_group_mapping_path.write_text(yaml.safe_dump(payload, sort_keys=True))

    @router.get("/user-groups")
    def list_user_groups(user: dict[str, Any] = Depends(get_current_user_context)) -> dict[str, Any]:
        enforce(user, "/user-groups", "GET")
        rows: list[dict[str, Any]] = []
        for user_id in sorted(list(user_ldap_groups.keys())):
            rows.append({"user_id": user_id, "groups": sorted(list(user_ldap_groups.get(user_id, set())))})
        return {"rows": rows}

    @router.post("/user-groups/add")
    def add_user_group(payload: UserGroupAdd, user: dict[str, Any] = Depends(get_current_user_context)) -> dict[str, Any]:
        enforce(user, "/user-groups/add", "POST")
        user_id = payload.user_id.strip()
        group = payload.group.strip()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user_id is required")
        if not group:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="group is required")

        user_ldap_groups.setdefault(user_id, set()).add(group)
        _write_userid_to_group_mapping()
        return {"status": "ok"}

    @router.post("/user-groups/remove")
    def remove_user_group(
        payload: UserGroupRemove, user: dict[str, Any] = Depends(get_current_user_context)
    ) -> dict[str, Any]:
        enforce(user, "/user-groups/remove", "POST")
        user_id = payload.user_id.strip()
        group = payload.group.strip()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user_id is required")
        if not group:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="group is required")

        if user_id in user_ldap_groups:
            user_ldap_groups[user_id].discard(group)
            if not user_ldap_groups[user_id]:
                user_ldap_groups.pop(user_id, None)
        _write_userid_to_group_mapping()
        return {"status": "ok"}

    return router
