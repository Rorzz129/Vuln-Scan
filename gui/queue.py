from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
import json
import uuid

APP_DIR = Path(__file__).resolve().parent.parent
QUEUE_FILE = APP_DIR / "scan_queue.json"


@dataclass
class QueueItem:
    id: str
    target: str
    profile: str
    status: str = "PENDING"
    result_summary: dict[str, Any] | None = None

    @classmethod
    def create(
        cls,
        target: str,
        profile: str,
    ) -> "QueueItem":
        return cls(
            id=uuid.uuid4().hex[:10],
            target=target.strip(),
            profile=profile.upper(),
        )


def load_queue() -> list[QueueItem]:
    try:
        data = json.loads(
            QUEUE_FILE.read_text(encoding="utf-8")
        )
    except Exception:
        return []

    items = []

    for raw in data if isinstance(data, list) else []:
        if not isinstance(raw, dict):
            continue

        try:
            items.append(
                QueueItem(
                    id=str(raw.get("id") or uuid.uuid4().hex[:10]),
                    target=str(raw.get("target") or ""),
                    profile=str(raw.get("profile") or "NORMAL"),
                    status=str(raw.get("status") or "PENDING"),
                    result_summary=raw.get("result_summary"),
                )
            )
        except Exception:
            continue

    return items


def save_queue(items: list[QueueItem]) -> None:
    QUEUE_FILE.write_text(
        json.dumps(
            [asdict(item) for item in items],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
