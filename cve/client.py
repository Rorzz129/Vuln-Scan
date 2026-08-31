from __future__ import annotations

from typing import Any

from cve.nvd_client import NVD_CVE_API_URL, nvd_paginated_get
from cve.parser import parse_cve, sort_cves


def _parse_results(
    raw_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in raw_results:
        raw_cve = item.get("cve")

        if not isinstance(raw_cve, dict):
            continue

        cve = parse_cve(raw_cve)
        cve_id = str(cve.get("id") or "").strip()

        if not cve_id or cve_id in seen:
            continue

        seen.add(cve_id)
        parsed.append(cve)

    return sort_cves(parsed)


def search_cves(
    cpe: str,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    if not str(cpe or "").strip():
        return []

    raw_results = nvd_paginated_get(
        NVD_CVE_API_URL,
        {"cpeName": cpe},
        result_key="vulnerabilities",
        limit=max(1, limit),
        results_per_page=min(max(1, limit), 100),
    )

    return _parse_results(raw_results)


def search_applicable_cves(
    concrete_cpe: str,
    *,
    limit: int = 500,
) -> list[dict[str, Any]]:
    if not str(concrete_cpe or "").strip():
        return []

    # NVD performs the applicability/range evaluation itself when cpeName is
    # supplied. isVulnerable further removes CPEs that only appear as
    # non-vulnerable environmental requirements in an applicability statement.
    params: list[tuple[str, Any]] = [
        ("cpeName", concrete_cpe),
        ("isVulnerable", ""),
    ]

    raw_results = nvd_paginated_get(
        NVD_CVE_API_URL,
        params,
        result_key="vulnerabilities",
        limit=max(1, limit),
        results_per_page=min(max(1, limit), 200),
    )

    return _parse_results(raw_results)
