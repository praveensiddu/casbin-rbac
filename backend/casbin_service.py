from __future__ import annotations

from pathlib import Path
from threading import RLock
from time import monotonic
from typing import Any

import casbin
from casbin.persist.adapters import FileAdapter
from fastapi import HTTPException, status

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore


_ENFORCER_LOCK = RLock()
_WATCHERS: list[Observer] = []


def build_enforcer(*, model_path: Path, policy_path: Path) -> casbin.Enforcer:
    adapter = FileAdapter(str(policy_path))
    e = casbin.Enforcer(str(model_path), adapter)
    with _ENFORCER_LOCK:
        e.load_policy()

    _start_policy_watcher(enforcer=e, policy_path=policy_path)
    return e


def _start_policy_watcher(*, enforcer: casbin.Enforcer, policy_path: Path) -> None:
    if Observer is None:
        return

    policy_path = policy_path.resolve()
    watch_dir = policy_path.parent
    target_name = policy_path.name

    class _PolicyReloadHandler(FileSystemEventHandler):
        def __init__(self) -> None:
            self._last_reload_at = 0.0

        def _maybe_reload(self, src_path: str | None) -> None:
            if not src_path:
                return
            try:
                if Path(src_path).name != target_name:
                    return
            except Exception:
                return

            now = monotonic()
            if now - self._last_reload_at < 0.25:
                return
            self._last_reload_at = now

            with _ENFORCER_LOCK:
                enforcer.load_policy()

        def on_modified(self, event) -> None:  # type: ignore[no-untyped-def]
            if getattr(event, "is_directory", False):
                return
            self._maybe_reload(getattr(event, "src_path", None))

        def on_created(self, event) -> None:  # type: ignore[no-untyped-def]
            if getattr(event, "is_directory", False):
                return
            self._maybe_reload(getattr(event, "src_path", None))

        def on_moved(self, event) -> None:  # type: ignore[no-untyped-def]
            if getattr(event, "is_directory", False):
                return
            self._maybe_reload(getattr(event, "dest_path", None))

    observer = Observer()
    observer.daemon = True
    observer.schedule(_PolicyReloadHandler(), str(watch_dir), recursive=False)
    observer.start()
    _WATCHERS.append(observer)


def enforce_rbac(
    *,
    enforcer: casbin.Enforcer,
    user: dict[str, Any],
    obj: str,
    act: str,
    applicationservice: dict[str, Any] | None = None,
) -> None:
    applicationservice_ctx = applicationservice or {"id": ""}
    with _ENFORCER_LOCK:
        allowed = enforcer.enforce(user, obj, act, applicationservice_ctx)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "Forbidden by RBAC", "roles": user.get("roles", []), "obj": obj, "act": act},
        )
