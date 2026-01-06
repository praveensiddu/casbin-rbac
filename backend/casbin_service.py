from __future__ import annotations

from pathlib import Path
from threading import RLock
from time import monotonic
from typing import Any

import casbin
from casbin.persist.adapters import FileAdapter
from fastapi import HTTPException, status


_ENFORCER_LOCK = RLock()
_POLICY_RELOAD_INTERVAL_SECONDS = 30 * 60
_LAST_POLICY_LOAD_AT = 0.0


def build_enforcer(*, model_path: Path, policy_path: Path) -> casbin.Enforcer:
    adapter = FileAdapter(str(policy_path))
    e = casbin.Enforcer(str(model_path), adapter)
    with _ENFORCER_LOCK:
        e.load_policy()

    global _LAST_POLICY_LOAD_AT
    _LAST_POLICY_LOAD_AT = monotonic()
    return e


def enforce_rbac(
    *,
    enforcer: casbin.Enforcer,
    usercontext: dict[str, Any],
    obj: str,
    act: str,
    applicationservice: dict[str, Any] | None = None,
) -> None:
    applicationservice_ctx = applicationservice or {"id": ""}
    with _ENFORCER_LOCK:
        global _LAST_POLICY_LOAD_AT
        now = monotonic()
        if now - _LAST_POLICY_LOAD_AT >= _POLICY_RELOAD_INTERVAL_SECONDS:
            enforcer.load_policy()
            _LAST_POLICY_LOAD_AT = now
        allowed = enforcer.enforce(usercontext, obj, act, applicationservice_ctx)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "Forbidden by RBAC", "roles": usercontext.get("roles", []), "obj": obj, "act": act},
        )
