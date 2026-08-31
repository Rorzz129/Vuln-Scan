from __future__ import annotations
from typing import Any

def _count_template_states(template_report: dict[str, Any]) -> dict[str, int]:
    stats = template_report.get("stats") or {}
    return {
        "total": int(stats.get("templates") or 0),
        "executed": int(stats.get("executed") or 0),
        "not_applicable": int(stats.get("not_applicable") or 0),
        "skipped": int(stats.get("skipped") or 0),
        "errors": int(stats.get("errors") or 0),
    }

def build_scan_health(
    *,
    http_status: int | None,
    web_report: dict[str, Any] | None,
    template_report: dict[str, Any] | None,
    cpe_diagnostics: list[dict[str, Any]] | None,
    profile: str,
) -> dict[str, Any]:
    web_report = web_report or {}
    template_report = template_report or {}
    cpe_diagnostics = cpe_diagnostics or []

    web_stats = web_report.get("stats") or {}
    web_planned = int(web_stats.get("planned_checks") or 0)
    web_executed = int(web_stats.get("executed_checks") or 0)
    web_skipped = int(web_stats.get("skipped_checks") or 0)
    web_errors = int(web_stats.get("errors") or 0)

    tpl = _count_template_states(template_report)

    cpe_resolved = sum(
        1 for item in cpe_diagnostics
        if item.get("status") == "RESOLVED"
    )
    cpe_unresolved = sum(
        1 for item in cpe_diagnostics
        if item.get("status") == "UNRESOLVED"
    )
    cpe_not_applicable = sum(
        1 for item in cpe_diagnostics
        if item.get("status") in {"SKIPPED", "NOT_APPLICABLE"}
    )

    # Coverage = completed / applicable work.
    # Technology/port/profile preconditions marked NOT_APPLICABLE do not lower it.
    applicable_web = web_planned
    applicable_templates = max(
        0,
        tpl["total"] - tpl["not_applicable"],
    )
    applicable_cpe = cpe_resolved + cpe_unresolved

    applicable_total = (
        applicable_web
        + applicable_templates
        + applicable_cpe
    )

    completed = (
        web_executed
        + tpl["executed"]
        + cpe_resolved
        + cpe_unresolved
    )

    skipped_applicable = (
        web_skipped
        + tpl["skipped"]
    )

    errors = web_errors + tpl["errors"]

    coverage = (
        100.0
        if applicable_total <= 0
        else round(
            min(
                100.0,
                max(
                    0.0,
                    completed / applicable_total * 100.0,
                ),
            ),
            1,
        )
    )

    reasons: list[str] = []

    if http_status is None:
        quality = "FAILED"
        reasons.append("No usable HTTP response was obtained.")
    elif http_status >= 500:
        quality = "DEGRADED"
        reasons.append(
            f"Base HTTP response was {http_status}; active HTTP checks were intentionally reduced."
        )
    elif errors:
        quality = "PARTIAL"
        reasons.append(f"{errors} scanner error(s) occurred.")
    elif skipped_applicable:
        quality = "PARTIAL"
        reasons.append(
            f"{skipped_applicable} applicable check(s) were skipped."
        )
    elif coverage < 90:
        quality = "PARTIAL"
        reasons.append(
            "Not all applicable scan work completed."
        )
    else:
        quality = "FULL"

    if cpe_unresolved:
        reasons.append(
            f"{cpe_unresolved} versioned technology/technologies were checked but could not be mapped to a reliable CPE."
        )

    if tpl["not_applicable"]:
        reasons.append(
            f"{tpl['not_applicable']} template(s) were not applicable to the detected target and were excluded from coverage."
        )

    if quality == "FULL" and coverage >= 95:
        confidence = "HIGH"
    elif quality in {"FULL", "PARTIAL"} and coverage >= 70:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    risk_available = (
        http_status is not None
        and http_status < 500
        and coverage >= 70
        and quality in {"FULL", "PARTIAL"}
    )

    return {
        "quality": quality,
        "coverage": coverage,
        "confidence": confidence,
        "risk_available": risk_available,
        "applicable": applicable_total,
        "executed": completed,
        "skipped": skipped_applicable,
        "not_applicable": tpl["not_applicable"] + cpe_not_applicable,
        "errors": errors,
        "profile": str(profile or "NORMAL").upper(),
        "http_status": http_status,
        "reasons": reasons,
        "components": {
            "web": {
                "applicable": applicable_web,
                "executed": web_executed,
                "skipped": web_skipped,
                "errors": web_errors,
            },
            "templates": {
                "total": tpl["total"],
                "applicable": applicable_templates,
                "executed": tpl["executed"],
                "not_applicable": tpl["not_applicable"],
                "skipped": tpl["skipped"],
                "errors": tpl["errors"],
            },
            "cpe": {
                "resolved": cpe_resolved,
                "unresolved": cpe_unresolved,
                "not_applicable": cpe_not_applicable,
            },
        },
    }
