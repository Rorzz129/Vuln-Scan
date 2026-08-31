from __future__ import annotations
from math import exp
from typing import Any

SEVERITY_POINTS = {
    "CRITICAL": 10.0,
    "HIGH": 8.0,
    "MEDIUM": 4.5,
    "LOW": 1.8,
    "INFO": 0.2,
    "UNKNOWN": 0.0,
}

CONFIDENCE_FACTOR = {
    "HIGH": 1.0,
    "MEDIUM": 0.75,
    "LOW": 0.5,
    "UNKNOWN": 0.4,
}

INFO_IDS = {
    "WEB-PATH-007",
    "WEB-PATH-008",
    "WEB-PATH-009",
    "WEB-HEADER-011",
    "WEB-HEADER-012",
    "WEB-METHOD-002",
    "WEB-METHOD-003",
}

VULNERABILITY_IDS = {
    "WEB-PATH-001",
    "WEB-PATH-002",
    "WEB-PATH-003",
    "WEB-PATH-004",
}

def classify_web_finding(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("classification") or "").upper()
    if explicit in {
        "VULNERABILITY",
        "MISCONFIGURATION",
        "EXPOSURE",
        "INFORMATION",
    }:
        return explicit

    finding_id = str(finding.get("id") or "").upper()
    severity = str(finding.get("severity") or "UNKNOWN").upper()
    category = str(finding.get("category") or "").casefold()

    if finding_id in VULNERABILITY_IDS:
        return "VULNERABILITY"

    if (
        "exposure" in category
        and severity not in {"INFO", "UNKNOWN"}
    ):
        return "EXPOSURE"

    if finding_id in INFO_IDS or severity == "INFO":
        return "INFORMATION"

    if finding_id.startswith(
        (
            "WEB-HEADER-",
            "WEB-CORS-",
            "WEB-COOKIE-",
            "WEB-METHOD-",
        )
    ):
        return "MISCONFIGURATION"

    return "MISCONFIGURATION"

def _saturate(points: float, scale: float) -> float:
    if points <= 0:
        return 0.0
    return round(
        min(
            100.0,
            100.0 * (1.0 - exp(-points / scale)),
        ),
        1,
    )

def _finding_points(finding: dict[str, Any]) -> float:
    severity = str(finding.get("severity") or "UNKNOWN").upper()
    confidence = str(finding.get("confidence") or "UNKNOWN").upper()

    points = SEVERITY_POINTS.get(severity, 0.0)
    points *= CONFIDENCE_FACTOR.get(confidence, 0.4)

    # Cookie hygiene should not dominate the global score.
    if str(finding.get("id") or "").upper().startswith("WEB-COOKIE-"):
        sensitivity = str(
            (finding.get("metadata") or {}).get(
                "cookie_sensitivity",
                "UNKNOWN",
            )
        ).upper()

        if sensitivity == "LOW":
            points *= 0.35
        elif sensitivity == "MEDIUM":
            points *= 0.65

    # Informational items barely influence risk.
    if str(finding.get("category") or "").casefold() == "technology":
        return 0.0

    if classify_web_finding(finding) == "INFORMATION":
        points *= 0.1

    return points

def _cve_points(vulnerability: dict[str, Any]) -> float:
    cve = vulnerability.get("cve") or {}

    try:
        base = float(cve.get("cvss"))
    except (TypeError, ValueError):
        base = SEVERITY_POINTS.get(
            str(cve.get("severity") or "UNKNOWN").upper(),
            0.0,
        )

    confidence = str(
        vulnerability.get("confidence") or "MEDIUM"
    ).upper()

    return base * CONFIDENCE_FACTOR.get(
        confidence,
        0.75,
    )

def build_risk_summary(
    web_findings: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    unresolved_technologies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    web_findings = web_findings or []
    vulnerabilities = vulnerabilities or []
    unresolved_technologies = unresolved_technologies or []

    by_severity = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0,
    }

    by_class = {
        "VULNERABILITY": 0,
        "MISCONFIGURATION": 0,
        "EXPOSURE": 0,
        "INFORMATION": 0,
    }

    buckets = {
        "VULNERABILITY": 0.0,
        "MISCONFIGURATION": 0.0,
        "EXPOSURE": 0.0,
        "INFORMATION": 0.0,
    }

    for finding in web_findings:
        severity = str(
            finding.get("severity") or "UNKNOWN"
        ).upper()
        by_severity[
            severity if severity in by_severity else "UNKNOWN"
        ] += 1

        classification = classify_web_finding(finding)
        by_class[classification] = by_class.get(
            classification,
            0,
        ) + 1
        buckets[classification] += _finding_points(finding)

    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve") or {}
        severity = str(
            cve.get("severity") or "UNKNOWN"
        ).upper()
        by_severity[
            severity if severity in by_severity else "UNKNOWN"
        ] += 1
        by_class["VULNERABILITY"] += 1
        buckets["VULNERABILITY"] += _cve_points(vulnerability)

    vulnerability_risk = _saturate(
        buckets["VULNERABILITY"],
        13.0,
    )
    configuration_risk = _saturate(
        buckets["MISCONFIGURATION"],
        24.0,
    )
    exposure_risk = _saturate(
        buckets["EXPOSURE"],
        18.0,
    )
    information_risk = _saturate(
        buckets["INFORMATION"],
        30.0,
    )

    # Findings with no confirmed/applicable vulnerability should not create
    # an aggressive global score. Vulnerability risk remains dominant.
    overall = round(
        min(
            100.0,
            max(
                vulnerability_risk,
                0.52 * configuration_risk
                + 0.28 * exposure_risk
                + 0.03 * information_risk,
            ),
        ),
        1,
    )

    if overall >= 85:
        level = "CRITICAL"
    elif overall >= 65:
        level = "HIGH"
    elif overall >= 40:
        level = "MEDIUM"
    elif overall >= 15:
        level = "LOW"
    else:
        level = "MINIMAL"

    return {
        "score": overall,
        "level": level,
        "components": {
            "vulnerability": vulnerability_risk,
            "configuration": configuration_risk,
            "exposure": exposure_risk,
            "information": information_risk,
        },
        "by_severity": by_severity,
        "by_classification": by_class,
        "unresolved_technologies": len(unresolved_technologies),
        "total_web_findings": len(web_findings),
        "total_applicable_cves": len(vulnerabilities),
    }
