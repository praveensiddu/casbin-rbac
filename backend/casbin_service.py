from __future__ import annotations

from pathlib import Path
from typing import Any

import casbin
from casbin.persist.adapters import FileAdapter
from fastapi import HTTPException, status


def build_enforcer(*, model_path: Path, policy_path: Path) -> casbin.Enforcer:
    adapter = FileAdapter(str(policy_path))
    e = casbin.Enforcer(str(model_path), adapter)
    e.load_policy()
    return e


def enforce(
    *,
    enforcer: casbin.Enforcer,
    user: dict[str, Any],
    obj: str,
    act: str,
    applicationservice: dict[str, Any] | None = None,
) -> None:
    applicationservice_ctx = applicationservice or {"id": ""}
    enforcer.load_policy()
    allowed = enforcer.enforce(user, obj, act, applicationservice_ctx)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "Forbidden by RBAC", "roles": user.get("roles", []), "obj": obj, "act": act},
        )
