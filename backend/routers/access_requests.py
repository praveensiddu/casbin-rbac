from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel


class AccessRequestCreate(BaseModel):
    applicationservice_id: str
    role: str
    group: str


def create_access_requests_router(
    *,
    enforce: Callable[[dict[str, Any], str, str], None],
    get_current_user: Callable[..., dict[str, Any]],
    access_requests_path: Path,
    applicationservices: dict[str, dict[str, str]],
) -> APIRouter:
    router = APIRouter()

    def _read_requests() -> list[dict[str, Any]]:
        if not access_requests_path.exists():
            return []
        raw = yaml.safe_load(access_requests_path.read_text()) or {}
        items = raw.get("requests")
        if not isinstance(items, list):
            return []
        out: list[dict[str, Any]] = []
        for it in items:
            if isinstance(it, dict):
                out.append(it)
        return out

    def _write_requests(requests: list[dict[str, Any]]) -> None:
        access_requests_path.write_text(yaml.safe_dump({"requests": requests}, sort_keys=True))

    @router.get("/access-requests/applicationservices")
    def list_applicationservices(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/access-requests/applicationservices", "GET")
        rows = []
        for app_id in sorted(list(applicationservices.keys())):
            rows.append({"applicationservice_id": app_id, "content": applicationservices[app_id].get("content", "")})
        return {"rows": rows}

    @router.post("/access-requests/request")
    def create_request(payload: AccessRequestCreate, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/access-requests/request", "POST")

        role = payload.role.strip()
        if role not in {"viewer", "recertify"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

        app_id = payload.applicationservice_id.strip()
        if app_id not in applicationservices:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")

        group = payload.group.strip()
        if not group:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group is required")

        requests = _read_requests()
        requested_by = str(user.get("username", ""))
        req = {
            "id": str(uuid4()),
            "requested_by": requested_by,
            "username": requested_by,
            "applicationservice_id": app_id,
            "role": role,
            "group": group,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        requests.append(req)
        _write_requests(requests)
        return {"status": "ok", "request": req}

    @router.get("/access-requests/me")
    def my_requests(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/access-requests/me", "GET")
        requested_by = str(user.get("username", ""))
        mine = [
            r
            for r in _read_requests()
            if str(r.get("requested_by") or r.get("username") or "") == requested_by
        ]
        mine.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
        return {"requests": mine}

    @router.get("/access-requests/all")
    def all_requests(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        enforce(user, "/access-requests/all", "GET")
        items = _read_requests()
        items.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
        return {"requests": items}

    return router
