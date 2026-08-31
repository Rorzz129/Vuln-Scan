from __future__ import annotations

from pathlib import Path
import json
import re

APP_DIR = Path(__file__).resolve().parent.parent
WORKSPACES_DIR = APP_DIR / "workspaces"

def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())[:100] or "workspace"

def _path(target: str) -> Path:
    return WORKSPACES_DIR / f"{_safe(target)}.json"

def load_workspace(target: str) -> dict:
    path = _path(target)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    return {
        "target": target,
        "scope": [],
        "notes": "",
        "last_scan": None,
    }

def save_workspace(target: str, data: dict) -> str:
    WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
    path = _path(target)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)

def update_workspace_from_scan(result: dict) -> str:
    target = (result.get("target") or {}).get("original") or "unknown"
    data = load_workspace(target)
    data["last_scan"] = {
        "profile": result.get("profile"),
        "duration": result.get("duration"),
        "risk": result.get("risk"),
        "health": result.get("scan_health"),
        "reports": result.get("reports"),
        "assets": result.get("assets"),
        "crawl": result.get("crawl"),
    }
    return save_workspace(target, data)
