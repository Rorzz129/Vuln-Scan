from __future__ import annotations
from time import perf_counter
from typing import Any

from analysis.profiles import get_profile
from web_checks.common import (
    build_context,
    deduplicate_findings,
    sort_findings,
    clear_http_cache,
    http_cache_stats,
)
from web_checks.cookies import check_cookies
from web_checks.cors import check_cors
from web_checks.http_methods import check_http_methods
from web_checks.security_headers import check_security_headers
from web_checks.sensitive_paths import check_sensitive_paths
from web_checks.transport import check_transport
from web_checks.auth_analyzer import check_auth
from web_checks.discovery import check_discovery
from web_checks.js_intelligence import check_js_intelligence
from web_checks.page_security import check_page_security

CHECKS = {
    "security_headers": check_security_headers,
    "cookies": check_cookies,
    "cors": check_cors,
    "http_methods": check_http_methods,
    "sensitive_paths": check_sensitive_paths,
    "transport": check_transport,
    "discovery": check_discovery,
    "js_intelligence": check_js_intelligence,
    "page_security": check_page_security,
}

ACTIVE_ON_HEALTHY = {
    "cors",
    "http_methods",
    "sensitive_paths",
    "js_intelligence",
    "page_security",
}

def _name(key: str) -> str:
    return key.replace("_", " ").title()

def scan_web(
    url: str,
    verbose: bool = True,
    profile: str = "NORMAL",
) -> dict[str, Any]:
    selected = get_profile(profile)
    clear_http_cache()
    started = perf_counter()

    context = build_context(url)
    findings = []
    errors = []
    checks = []
    skipped_checks = []

    try:
        if verbose:
            print(f"[+] Starting web security scan: {context.requested_url}")
            print(f"[+] Profile: {selected.name} - {selected.description}")
            print(f"[+] Base response: HTTP {context.status_code}")

        selected_keys = [
            key
            for key in selected.web_checks
            if key in CHECKS
        ]

        for key in selected_keys:
            check = CHECKS[key]
            name = _name(key)

            if context.degraded and key in ACTIVE_ON_HEALTHY:
                reason = (
                    f"skipped because base response is HTTP {context.status_code}"
                )
                skipped_checks.append({
                    "name": name,
                    "reason": reason,
                })
                checks.append({
                    "name": name,
                    "findings": 0,
                    "duration": 0.0,
                    "error": None,
                    "status": "SKIPPED",
                    "reason": reason,
                })
                if verbose:
                    print(f"[>] {name}: SKIPPED ({reason})")
                continue

            check_started = perf_counter()

            try:
                results = check(context)
                valid = [
                    item
                    for item in results
                    if isinstance(item, dict)
                ]
                findings.extend(valid)
                error = None
                status = "EXECUTED"
            except Exception as exc:
                valid = []
                error = f"{type(exc).__name__}: {exc}"
                errors.append({
                    "check": name,
                    "error": error,
                })
                status = "ERROR"

            duration = perf_counter() - check_started
            checks.append({
                "name": name,
                "findings": len(valid),
                "duration": round(duration, 3),
                "error": error,
                "status": status,
                "reason": None,
            })

            if verbose:
                if error:
                    print(f"[!] {name}: {error}")
                else:
                    print(
                        f"[+] {name}: {len(valid)} finding(s) ({duration:.2f}s)"
                    )

        findings = sort_findings(
            deduplicate_findings(findings)
        )
        duration = perf_counter() - started
        executed_checks = sum(
            1 for item in checks
            if item["status"] == "EXECUTED"
        )

        report = {
            "url": context.url,
            "status_code": context.status_code,
            "mode": "LIMITED" if context.degraded else "FULL",
            "profile": selected.name,
            "findings": findings,
            "errors": errors,
            "notes": list(context.notes),
            "checks": checks,
            "skipped_checks": skipped_checks,
            "cache": http_cache_stats(),
            "stats": {
                "planned_checks": len(selected_keys),
                "executed_checks": executed_checks,
                "skipped_checks": len(skipped_checks),
                "findings": len(findings),
                "errors": len(errors),
                "duration": round(duration, 3),
            },
        }

        if verbose:
            print(
                f"[+] Scan complete: {len(findings)} finding(s), "
                f"{len(errors)} error(s), mode={report['mode']}, "
                f"{duration:.2f}s"
            )
            cache = report["cache"]
            print(
                f"[+] HTTP cache: {cache.get('hits', 0)} hit(s) / "
                f"{cache.get('misses', 0)} miss(es)"
            )

        return report

    finally:
        context.session.close()

def scan_web_security(
    url: str,
    verbose: bool = True,
    profile: str = "NORMAL",
) -> list[dict[str, Any]]:
    return scan_web(
        url,
        verbose=verbose,
        profile=profile,
    )["findings"]
