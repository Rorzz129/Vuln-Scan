from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "NONE": 1,
    "UNKNOWN": 0,
}


def _description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])

    if not isinstance(descriptions, list):
        return ""

    for language in ("en", "fr"):
        for item in descriptions:
            if (
                isinstance(item, dict)
                and item.get("lang") == language
                and item.get("value")
            ):
                return str(item["value"]).strip()

    for item in descriptions:
        if isinstance(item, dict) and item.get("value"):
            return str(item["value"]).strip()

    return ""


def _references(cve: dict[str, Any]) -> list[str]:
    references = cve.get("references", [])
    results: list[str] = []

    if not isinstance(references, list):
        return results

    for reference in references:
        if not isinstance(reference, dict):
            continue

        url = str(reference.get("url") or "").strip()

        if url and url not in results:
            results.append(url)

    return results


def _weaknesses(cve: dict[str, Any]) -> list[str]:
    weaknesses = cve.get("weaknesses", [])
    values: list[str] = []

    if not isinstance(weaknesses, list):
        return values

    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue

        descriptions = weakness.get("description", [])

        if not isinstance(descriptions, list):
            continue

        for item in descriptions:
            if not isinstance(item, dict):
                continue

            value = str(item.get("value") or "").strip()

            if value and value not in values:
                values.append(value)

    return values


def _metric_candidates(cve: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = cve.get("metrics", {})

    if not isinstance(metrics, dict):
        return []

    candidates: list[dict[str, Any]] = []

    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key, [])

        if not isinstance(entries, list):
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            data = entry.get("cvssData", {})

            if not isinstance(data, dict):
                continue

            try:
                score = (
                    float(data.get("baseScore"))
                    if data.get("baseScore") is not None
                    else None
                )
            except (TypeError, ValueError):
                score = None

            candidates.append({
                "version": version,
                "score": score,
                "severity": str(
                    data.get("baseSeverity")
                    or entry.get("baseSeverity")
                    or "UNKNOWN"
                ).upper(),
                "vector": data.get("vectorString"),
            })

    return candidates


def _best_metric(cve: dict[str, Any]) -> dict[str, Any]:
    candidates = _metric_candidates(cve)

    if not candidates:
        return {
            "version": None,
            "score": None,
            "severity": "UNKNOWN",
            "vector": None,
        }

    version_order = {
        "4.0": 4,
        "3.1": 3,
        "3.0": 2,
        "2.0": 1,
    }

    candidates.sort(
        key=lambda item: (
            version_order.get(str(item.get("version")), 0),
            item.get("score") if item.get("score") is not None else -1,
        ),
        reverse=True,
    )

    return candidates[0]


def parse_cve(
    cve: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(cve, dict):
        raise TypeError("CVE must be a dictionary")

    metric = _best_metric(cve)

    return {
        "id": str(cve.get("id") or "").strip(),
        "status": cve.get("vulnStatus"),
        "description": _description(cve),
        "cvss": metric["score"],
        "cvss_version": metric["version"],
        "cvss_vector": metric["vector"],
        "severity": metric["severity"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "weaknesses": _weaknesses(cve),
        "references": _references(cve),
        "source_identifier": cve.get("sourceIdentifier"),
    }


def sort_cves(
    cves: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        cves,
        key=lambda cve: (
            -SEVERITY_ORDER.get(
                str(cve.get("severity") or "UNKNOWN").upper(),
                0,
            ),
            -float(cve.get("cvss") or 0),
            str(cve.get("id") or ""),
        ),
    )
