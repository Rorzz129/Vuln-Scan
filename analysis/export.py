from __future__ import annotations

from pathlib import Path
from typing import Any
import csv


def export_findings_csv(
    findings: list[dict[str, Any]],
    path: str | Path,
) -> str:
    path = Path(path)
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    headers = [
        "id",
        "severity",
        "classification",
        "verification",
        "title",
        "confidence",
        "category",
        "url",
        "evidence",
        "recommendation",
    ]

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=headers,
        )
        writer.writeheader()

        for finding in findings or []:
            writer.writerow(
                {
                    key: finding.get(key, "")
                    for key in headers
                }
            )

    return str(path)
