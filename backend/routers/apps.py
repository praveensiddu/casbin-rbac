from __future__ import annotations

from typing import Any, Callable
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel


class FlowCreate(BaseModel):
    name: str
    content: str = ""


def create_apps_router(
    *,
    enforce: Callable[[dict[str, Any], str, str, dict[str, Any] | None], None],
    get_current_user_context: Callable[..., dict[str, Any]],
    applicationservices: dict[str, dict[str, str]],
    app_flows: dict[str, list[dict[str, Any]]],
) -> APIRouter:
    router = APIRouter()

    @router.get("/apps")
    def list_apps(user_context: dict[str, Any] = Depends(get_current_user_context)) -> dict[str, Any]:
        enforce(user_context, "/apps", "GET", None)
        rows: list[dict[str, Any]] = []
        for applicationservice_id in sorted(list(applicationservices.keys())):
            rows.append(
                {
                    "applicationservice_id": applicationservice_id,
                    "content": applicationservices[applicationservice_id].get("content", ""),
                }
            )
        return {"rows": rows}

    @router.get("/apps/{applicationservice_id}")
    def get_applicationservice(
        applicationservice_id: str, user_context: dict[str, Any] = Depends(get_current_user_context)
    ) -> dict[str, Any]:
        enforce(
            user_context,
            f"/apps/{applicationservice_id}",
            "GET",
            {"id": applicationservice_id},
        )
        applicationservice = applicationservices.get(applicationservice_id)
        if not applicationservice:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
        return {
            "applicationservice_id": applicationservice_id,
            "content": applicationservice["content"],
            "user": user_context,
        }

    @router.get("/apps/{applicationservice_id}/flows")
    def list_flows(
        applicationservice_id: str, user_context: dict[str, Any] = Depends(get_current_user_context)
    ) -> dict[str, Any]:
        enforce(
            user_context,
            f"/flows/{applicationservice_id}",
            "GET",
            {"id": applicationservice_id},
        )
        if applicationservice_id not in applicationservices:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
        return {"rows": app_flows.get(applicationservice_id, [])}

    @router.post("/apps/{applicationservice_id}/flows")
    def create_flow(
        applicationservice_id: str,
        payload: FlowCreate,
        user_context: dict[str, Any] = Depends(get_current_user_context),
    ) -> dict[str, Any]:
        enforce(
            user_context,
            f"/flows/{applicationservice_id}",
            "POST",
            {"id": applicationservice_id},
        )
        if applicationservice_id not in applicationservices:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")

        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Flow name is required")

        flow = {"id": str(uuid4()), "name": name, "content": payload.content}
        app_flows.setdefault(applicationservice_id, []).append(flow)
        return {"status": "ok", "flow": flow}

    @router.put("/apps/{applicationservice_id}")
    def update_applicationservice(
        applicationservice_id: str, user_context: dict[str, Any] = Depends(get_current_user_context)
    ) -> dict[str, Any]:
        enforce(
            user_context,
            f"/apps/{applicationservice_id}",
            "PUT",
            {"id": applicationservice_id},
        )
        if applicationservice_id not in applicationservices:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
        return {"applicationservice_id": applicationservice_id, "message": "Updated", "user": user_context}

    @router.delete("/apps/{applicationservice_id}")
    def delete_applicationservice(
        applicationservice_id: str, user_context: dict[str, Any] = Depends(get_current_user_context)
    ) -> dict[str, Any]:
        enforce(
            user_context,
            f"/apps/{applicationservice_id}",
            "DELETE",
            {"id": applicationservice_id},
        )
        if applicationservice_id not in applicationservices:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ApplicationService not found")
        return {"applicationservice_id": applicationservice_id, "message": "Deleted", "user": user_context}

    return router
