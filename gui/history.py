from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json

APP_DIR = Path(__file__).resolve().parent.parent
HISTORY_FILE = APP_DIR / "scan_history.json"
MAX_HISTORY = 100


def load_history() -> list[dict]:
    try:
        data = json.loads(
            HISTORY_FILE.read_text(encoding="utf-8")
        )
        if isinstance(data, list):
            return [
                item
                for item in data
                if isinstance(item, dict)
            ]
    except Exception:
        pass

    return []


def save_history(items: list[dict]) -> None:
    HISTORY_FILE.write_text(
        json.dumps(
            items[:MAX_HISTORY],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def append_history(result: dict) -> dict:
    target = result.get("target") or {}
    risk = result.get("risk") or {}
    health = result.get("scan_health") or {}
    reports = result.get("reports") or {}

    item = {
        "timestamp": datetime.now(
            timezone.utc
        ).astimezone().isoformat(
            timespec="seconds"
        ),
        "target": target.get("original") or "",
        "ip": target.get("ip") or "",
        "profile": result.get("profile") or "",
        "quality": health.get("quality") or "",
        "coverage": health.get("coverage"),
        "risk_score": (
            risk.get("score")
            if health.get("risk_available", True)
            else None
        ),
        "risk_level": risk.get("level") or "",
        "findings": len(
            result.get("findings") or []
        ),
        "cves": len(
            result.get("vulnerabilities") or []
        ),
        "duration": result.get("duration"),
        "json_report": reports.get("json"),
        "html_report": reports.get("html"),
        "snapshot": {
            "nmap": result.get("nmap") or {},
            "technologies": result.get("technologies") or [],
            "findings": result.get("findings") or [],
            "vulnerabilities": result.get("vulnerabilities") or [],
        },
    }

    items = load_history()
    items.insert(0, item)
    save_history(items)

    return item


def clear_history() -> None:
    save_history([])

def latest_snapshot_for_target(target: str) -> dict | None:
    for item in load_history():
        if str(item.get("target") or "") == str(target or ""):
            snapshot = item.get("snapshot")
            if isinstance(snapshot, dict):
                return snapshot
    return None
