from __future__ import annotations
from pathlib import Path
import json

def list_templates(directory: str | Path) -> list[dict]:
    root = Path(directory)
    if not root.exists():
        return []

    items = []
    for path in sorted(root.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        items.append({
            "path": str(path),
            "enabled": bool(data.get("enabled", True)),
            "id": str(data.get("id") or ""),
            "name": str(data.get("name") or path.stem),
            "severity": str(data.get("severity") or ""),
            "tags": list(data.get("tags") or []),
        })

    return items

def toggle_template(path: str | Path, enabled: bool) -> None:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["enabled"] = bool(enabled)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
