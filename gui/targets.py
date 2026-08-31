from __future__ import annotations

from pathlib import Path
import json

APP_DIR = Path(__file__).resolve().parent.parent
TARGETS_FILE = APP_DIR / "saved_targets.json"


def load_targets() -> list[dict]:
    try:
        data = json.loads(
            TARGETS_FILE.read_text(encoding="utf-8")
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


def save_targets(items: list[dict]) -> None:
    TARGETS_FILE.write_text(
        json.dumps(
            items,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def add_target(
    target: str,
    label: str = "",
    profile: str = "NORMAL",
) -> None:
    target = target.strip()

    if not target:
        return

    items = load_targets()

    for item in items:
        if str(item.get("target") or "").casefold() == target.casefold():
            item["label"] = label.strip()
            item["profile"] = profile.upper()
            save_targets(items)
            return

    items.append(
        {
            "target": target,
            "label": label.strip(),
            "profile": profile.upper(),
        }
    )

    save_targets(items)


def remove_target(target: str) -> None:
    items = [
        item
        for item in load_targets()
        if str(item.get("target") or "").casefold()
        != str(target or "").casefold()
    ]
    save_targets(items)
