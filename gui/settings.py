from __future__ import annotations

from pathlib import Path
import json

APP_DIR = Path(__file__).resolve().parent.parent
SETTINGS_FILE = APP_DIR / "acr_vuln_settings.json"

DEFAULTS = {
    "profile": "NORMAL",
    "save_json": True,
    "save_html": True,
    "reports_dir": str(APP_DIR / "reports"),
    "templates_dir": str(APP_DIR / "templates"),
    "max_cves": 500,
    "auto_open_report": False,
    "remember_target": False,
    "last_target": "",
    "compact_tables": False,
    "history_enabled": True,
    "confirm_before_scan": False,
    "allow_subdomains": True,
    "scope_exclusions": "",
    "resume_enabled": True,
}


def load_settings() -> dict:
    settings = dict(DEFAULTS)

    try:
        data = json.loads(
            SETTINGS_FILE.read_text(encoding="utf-8")
        )
        if isinstance(data, dict):
            settings.update(data)
    except Exception:
        pass

    return settings


def save_settings(settings: dict) -> None:
    SETTINGS_FILE.write_text(
        json.dumps(settings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
