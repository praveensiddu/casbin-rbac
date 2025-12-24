from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text())
    return data or {}


def load_userid_to_group_mapping(base_dir: Path) -> dict[str, set[str]]:
    raw = load_yaml(base_dir / "userid_to_group_mapping.yaml")
    return {str(user): set(map(str, groups or [])) for user, groups in raw.items()}


def load_roles_4_groups2global(base_dir: Path) -> dict[str, set[str]]:
    raw = load_yaml(base_dir / "roles_4_groups2global.yaml")
    return {str(group): set(map(str, roles or [])) for group, roles in raw.items()}


def load_roles_4_users2global(base_dir: Path) -> dict[str, set[str]]:
    raw = load_yaml(base_dir / "roles_4_users2global.yaml")
    return {str(user): set(map(str, roles or [])) for user, roles in raw.items()}


def load_roles_4_group2applicationservice(base_dir: Path) -> dict[str, dict[str, set[str]]]:
    raw = load_yaml(base_dir / "roles_4_group2applicationservice.yaml")
    out: dict[str, dict[str, set[str]]] = {}
    for group, doc_map in raw.items():
        group_s = str(group)
        out[group_s] = {}
        if not doc_map:
            continue
        for doc_id, roles in doc_map.items():
            out[group_s][str(doc_id)] = set(map(str, roles or []))
    return out


def load_applicationservices(base_dir: Path) -> dict[str, dict[str, str]]:
    raw = load_yaml(base_dir / "applicationservices.yaml")
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
