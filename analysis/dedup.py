from __future__ import annotations

from typing import Any
from urllib.parse import (
    urlsplit,
    urlunsplit,
)
import re

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}

CONFIDENCE_ORDER = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

VERIFICATION_ORDER = {
    "CONFIRMED": 4,
    "OBSERVED": 3,
    "INFERRED": 2,
    "UNCONFIRMED": 1,
    "UNKNOWN": 0,
}

CONCEPT_RULES = (
    (
        "api-docs",
        (
            "api-docs",
            "swagger",
            "openapi",
            "api documentation",
        ),
    ),
    (
        "git-exposure",
        (
            "/.git/",
            "git metadata",
            "git repository",
        ),
    ),
    (
        "env-exposure",
        (
            "/.env",
            "environment file",
        ),
    ),
    (
        "server-status",
        (
            "server-status",
            "apache server status",
        ),
    ),
    (
        "directory-listing",
        (
            "directory listing",
            "index of /",
        ),
    ),
    (
        "server-disclosure",
        (
            "server software information disclosed",
            "server header disclosure",
        ),
    ),
    (
        "hsts-missing",
        (
            "strict-transport-security header missing",
            "hsts absent",
        ),
    ),
    (
        "angular-marker",
        (
            "angular application marker",
            "html signature: <app-root>",
        ),
    ),
)

def _normalize_url(
    value: Any,
) -> str:
    try:
        parsed = urlsplit(
            str(value or "")
        )

        path = re.sub(
            r"/+$",
            "",
            parsed.path
            or "/",
        ) or "/"

        return urlunsplit(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                path,
                "",
                "",
            )
        )
    except Exception:
        return str(
            value or ""
        ).strip().lower()

def _concept(
    finding: dict[str, Any],
) -> str:
    explicit = str(
        finding.get("concept")
        or ""
    ).strip().casefold()

    if explicit:
        return explicit

    blob = " ".join(
        [
            str(
                finding.get("id")
                or ""
            ),
            str(
                finding.get("title")
                or ""
            ),
            str(
                finding.get("category")
                or ""
            ),
            str(
                finding.get("url")
                or ""
            ),
            str(
                finding.get("evidence")
                or ""
            ),
        ]
    ).casefold()

    for (
        concept,
        needles,
    ) in CONCEPT_RULES:
        if any(
            needle.casefold()
            in blob
            for needle
            in needles
        ):
            return concept

    title = re.sub(
        r"[^a-z0-9]+",
        " ",
        str(
            finding.get(
                "title"
            )
            or ""
        ).casefold(),
    ).strip()

    return (
        title
        or str(
            finding.get("id")
            or "unknown"
        ).casefold()
    )

def _quality(
    finding: dict[str, Any],
) -> tuple[
    int,
    int,
    int,
    int,
]:
    return (
        VERIFICATION_ORDER.get(
            str(
                finding.get(
                    "verification",
                    "UNKNOWN",
                )
            ).upper(),
            0,
        ),
        SEVERITY_ORDER.get(
            str(
                finding.get(
                    "severity",
                    "UNKNOWN",
                )
            ).upper(),
            0,
        ),
        CONFIDENCE_ORDER.get(
            str(
                finding.get(
                    "confidence",
                    "UNKNOWN",
                )
            ).upper(),
            0,
        ),
        1
        if (
            finding.get("source")
            == "web-check"
        )
        else 0,
    )

def merge_findings(
    *groups: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    merged: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    duplicate_count = 0

    for group in groups:
        for raw in (
            group
            or []
        ):
            if not isinstance(
                raw,
                dict,
            ):
                continue

            finding = dict(
                raw
            )

            finding.setdefault(
                "source",
                "web-check",
            )

            finding.setdefault(
                "verification",
                "OBSERVED",
            )

            url = _normalize_url(
                finding.get(
                    "url"
                )
            )

            key = (
                url,
                _concept(
                    finding
                ),
            )

            existing = (
                merged.get(
                    key
                )
            )

            if existing is None:
                finding[
                    "sources"
                ] = [
                    finding.get(
                        "source"
                    )
                ]

                finding[
                    "related_ids"
                ] = [
                    str(
                        finding.get(
                            "id"
                        )
                        or ""
                    )
                ]

                finding[
                    "merged_evidence"
                ] = [
                    str(
                        finding.get(
                            "evidence"
                        )
                        or ""
                    )
                ]

                merged[
                    key
                ] = finding
                continue

            duplicate_count += 1

            if (
                _quality(
                    finding
                )
                > _quality(
                    existing
                )
            ):
                winner = finding
            else:
                winner = existing

            result = dict(
                winner
            )

            sources = list(
                existing.get(
                    "sources"
                )
                or [
                    existing.get(
                        "source"
                    )
                ]
            )

            for source in [
                finding.get(
                    "source"
                ),
                *(
                    finding.get(
                        "sources"
                    )
                    or []
                ),
            ]:
                if (
                    source
                    and source
                    not in sources
                ):
                    sources.append(
                        source
                    )

            ids = list(
                existing.get(
                    "related_ids"
                )
                or [
                    str(
                        existing.get(
                            "id"
                        )
                        or ""
                    )
                ]
            )

            for item in [
                str(
                    finding.get(
                        "id"
                    )
                    or ""
                ),
                *(
                    finding.get(
                        "related_ids"
                    )
                    or []
                ),
            ]:
                if (
                    item
                    and item
                    not in ids
                ):
                    ids.append(
                        item
                    )

            evidence = list(
                existing.get(
                    "merged_evidence"
                )
                or [
                    str(
                        existing.get(
                            "evidence"
                        )
                        or ""
                    )
                ]
            )

            for item in [
                str(
                    finding.get(
                        "evidence"
                    )
                    or ""
                ),
                *(
                    finding.get(
                        "merged_evidence"
                    )
                    or []
                ),
            ]:
                if (
                    item
                    and item
                    not in evidence
                ):
                    evidence.append(
                        item
                    )

            result[
                "sources"
            ] = sources
            result[
                "related_ids"
            ] = ids
            result[
                "merged_evidence"
            ] = evidence
            result[
                "duplicate_count"
            ] = (
                len(ids)
                - 1
            )

            merged[
                key
            ] = result

    findings = list(
        merged.values()
    )

    findings.sort(
        key=lambda finding: (
            -SEVERITY_ORDER.get(
                str(
                    finding.get(
                        "severity",
                        "UNKNOWN",
                    )
                ).upper(),
                0,
            ),
            str(
                finding.get(
                    "title"
                )
                or ""
            ).casefold(),
        )
    )

    return {
        "findings": findings,
        "duplicates_removed": duplicate_count,
    }
