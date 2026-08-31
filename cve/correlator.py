from __future__ import annotations

from typing import Any

from cve.engine import scan_technology_cves


def correlate_cves(
    technologies: list[dict[str, Any]],
    *,
    verbose: bool = True,
) -> list[dict[str, Any]]:
    results = scan_technology_cves(
        technologies,
        verbose=verbose,
    )

    correlated: list[dict[str, Any]] = []

    for result in results:
        cve = dict(result.get("cve") or {})
        cve["technology"] = result.get("technology")
        cve["version"] = result.get("version")
        cve["port"] = result.get("port")
        cve["cpe"] = result.get("cpe")
        cve["cpe_score"] = result.get("cpe_score")
        cve["match_mode"] = result.get("match_mode")
        cve["status"] = result.get("status", "APPLICABLE")
        correlated.append(cve)

    return correlated
