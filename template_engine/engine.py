from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import urljoin

from analysis.profiles import get_profile
from technology_intel.aliases import canonical_name
from template_engine.loader import load_templates
from template_engine.matchers import (
    match_response,
    extract_values,
)
from web_checks.accuracy import (
    build_soft404_baselines,
    looks_like_soft404,
    content_type_matches,
    same_origin,
)
from web_checks.common import (
    create_session,
    normalize_url,
    cached_request,
    http_cache_stats,
)

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}

def _technology_names(
    technologies: list[dict[str, Any]] | None,
) -> set[str]:
    result: set[str] = set()

    for item in technologies or []:
        if not isinstance(item, dict):
            continue

        name = str(
            item.get("name")
            or item.get("canonical_name")
            or ""
        ).strip()

        if name:
            result.add(
                name.casefold()
            )
            result.add(
                canonical_name(
                    name
                ).casefold()
            )

        for alias in item.get("aliases") or []:
            result.add(
                str(alias).casefold()
            )

    return result

def _ports(
    technologies: list[dict[str, Any]] | None,
) -> set[int]:
    result = set()

    for item in technologies or []:
        try:
            if item.get("port") is not None:
                result.add(int(item["port"]))
        except Exception:
            pass

    return result

def _precondition(
    template: Any,
    technologies: list[dict[str, Any]] | None,
    profile_level: int,
    *,
    base_status: int | None,
) -> tuple[str, str | None]:
    if template.min_profile > profile_level:
        return "NOT_APPLICABLE", f"requires profile level {template.min_profile}"

    names = _technology_names(technologies)

    if template.requires_technologies:
        required = [
            value.casefold()
            for value in template.requires_technologies
        ]

        if not any(
            any(req in name for name in names)
            for req in required
        ):
            return "NOT_APPLICABLE", "technology precondition not met"

    if template.excludes_technologies:
        excluded = [
            value.casefold()
            for value in template.excludes_technologies
        ]

        if any(
            any(ex in name for name in names)
            for ex in excluded
        ):
            return "NOT_APPLICABLE", "excluded technology detected"

    if template.requires_ports:
        present = _ports(technologies)

        if not any(
            port in present
            for port in template.requires_ports
        ):
            return "NOT_APPLICABLE", "port precondition not met"

    if template.requires_http_status:
        if base_status not in set(template.requires_http_status):
            return "NOT_APPLICABLE", "HTTP status precondition not met"

    if (
        base_status is not None
        and base_status >= 500
        and not template.allow_degraded
    ):
        return "SKIPPED", f"base HTTP status {base_status} is degraded"

    return "RUNNABLE", None

def _run_template(
    base_url: str,
    template: Any,
    baselines: list[Any],
) -> dict[str, Any]:
    started = perf_counter()
    session = create_session()
    matches = []
    total_requests = 0

    try:
        for req in template.requests:
            total_requests += 1
            target_url = urljoin(
                normalize_url(base_url),
                req.path,
            )

            response = cached_request(
                session,
                req.method,
                target_url,
                headers=req.headers,
                timeout=(3.0, req.timeout),
                allow_redirects=req.follow_redirects,
            )

            if (
                template.validation.require_same_origin
                and not same_origin(
                    base_url,
                    response.url,
                )
            ):
                continue

            if (
                template.validation.content_types
                and not content_type_matches(
                    response,
                    template.validation.content_types,
                )
            ):
                continue

            soft404_similarity = 0.0

            if (
                template.validation.reject_soft404
                and req.method == "GET"
            ):
                is_soft404, soft404_similarity = (
                    looks_like_soft404(
                        response,
                        baselines,
                        threshold=template.validation.max_soft404_similarity,
                    )
                )

                if is_soft404:
                    continue

            matched, evidence = match_response(
                response,
                template.matchers,
                template.matcher_condition,
            )

            extracted, missing_required = extract_values(
                response,
                template.extractors,
            )

            if missing_required:
                matched = False

            if matched:
                matches.append({
                    "url": response.url,
                    "status_code": response.status_code,
                    "evidence": evidence,
                    "extracted": extracted,
                    "soft404_similarity": round(
                        soft404_similarity,
                        3,
                    ),
                    "verification": template.validation.verification,
                })

                if template.stop_at_first_match:
                    break

        return {
            "template": template,
            "matched": bool(matches),
            "matches": matches,
            "requests": total_requests,
            "duration": round(
                perf_counter() - started,
                3,
            ),
            "error": None,
        }

    except Exception as exc:
        return {
            "template": template,
            "matched": False,
            "matches": [],
            "requests": total_requests,
            "duration": round(
                perf_counter() - started,
                3,
            ),
            "error": f"{type(exc).__name__}: {exc}",
        }

    finally:
        session.close()

def run_templates(
    base_url: str,
    template_dir: str | Path = "templates",
    *,
    workers: int | None = None,
    tags: set[str] | None = None,
    verbose: bool = True,
    technologies: list[dict[str, Any]] | None = None,
    profile: str = "NORMAL",
    base_status: int | None = None,
) -> dict[str, Any]:
    started = perf_counter()
    selected = get_profile(profile)

    baselines = []

    if (
        base_status is not None
        and base_status < 500
    ):
        try:
            from web_checks.common import build_context

            baseline_context = build_context(
                base_url
            )

            try:
                baselines = build_soft404_baselines(
                    baseline_context,
                    count=2,
                )
            finally:
                baseline_context.session.close()
        except Exception:
            baselines = []

    templates, load_errors = load_templates(
        template_dir
    )

    if tags:
        wanted = {
            tag.casefold()
            for tag in tags
        }
        templates = [
            template
            for template in templates
            if wanted.intersection(
                tag.casefold()
                for tag in template.tags
            )
        ]

    templates = [
        template
        for template in templates
        if template.enabled
    ]

    runnable = []
    skipped = []
    not_applicable = []
    planned_requests = 0

    for template in templates:
        state, reason = _precondition(
            template,
            technologies,
            selected.template_level,
            base_status=base_status,
        )

        request_cost = max(
            1,
            len(template.requests),
        )

        if state == "NOT_APPLICABLE":
            not_applicable.append({
                "template": template.id,
                "reason": reason,
                "status": "NOT_APPLICABLE",
            })
            continue

        if state == "SKIPPED":
            skipped.append({
                "template": template.id,
                "reason": reason,
                "status": "SKIPPED",
            })
            continue

        if (
            planned_requests + request_cost
            > selected.template_request_budget
        ):
            skipped.append({
                "template": template.id,
                "reason": (
                    f"profile request budget exceeded "
                    f"({selected.template_request_budget})"
                ),
                "status": "SKIPPED",
            })
            continue

        runnable.append(template)
        planned_requests += request_cost

    findings = []
    execution_errors = []
    executed_requests = 0

    if verbose:
        print(
            f"[+] Loaded {len(templates)} safe template(s) | "
            f"runnable={len(runnable)} "
            f"not_applicable={len(not_applicable)} "
            f"skipped={len(skipped)} | "
            f"budget={selected.template_request_budget} request(s)"
        )

    if not_applicable and verbose:
        reasons: dict[str, int] = {}

        for item in not_applicable:
            reason = str(
                item.get("reason")
                or "unknown"
            )
            reasons[reason] = (
                reasons.get(reason, 0) + 1
            )

        for reason, count in sorted(
            reasons.items()
        ):
            print(
                f"[>] {count} template(s) not applicable: {reason}"
            )

    if skipped and verbose:
        reasons: dict[str, int] = {}

        for item in skipped:
            reason = str(
                item.get("reason")
                or "unknown"
            )
            reasons[reason] = (
                reasons.get(reason, 0) + 1
            )

        for reason, count in sorted(
            reasons.items()
        ):
            print(
                f"[>] {count} template(s) skipped: {reason}"
            )

    if runnable:
        max_workers = (
            workers
            or selected.template_workers
        )

        with ThreadPoolExecutor(
            max_workers=max(
                1,
                min(
                    max_workers,
                    len(runnable),
                ),
            )
        ) as pool:
            futures = {
                pool.submit(
                    _run_template,
                    base_url,
                    template,
                    baselines,
                ): template
                for template in runnable
            }

            for future in as_completed(
                futures
            ):
                result = future.result()
                template = result["template"]
                executed_requests += int(
                    result.get("requests") or 0
                )

                if result["error"]:
                    execution_errors.append({
                        "template": template.id,
                        "error": result["error"],
                    })

                    if verbose:
                        print(
                            f"[!] {template.id}: "
                            f"{result['error']}"
                        )

                    continue

                if not result["matched"]:
                    continue

                for match in result["matches"]:
                    finding = {
                        "id": template.id,
                        "title": template.name,
                        "severity": template.severity,
                        "confidence": template.confidence,
                        "category": template.category,
                        "url": match["url"],
                        "status_code": match["status_code"],
                        "description": template.description,
                        "evidence": (
                            "; ".join(
                                match["evidence"]
                            )
                            or "Template matched"
                        ),
                        "recommendation": template.recommendation,
                        "tags": template.tags,
                        "source": "template-engine",
                        "extracted": match["extracted"],
                        "verification": match.get(
                            "verification",
                            "OBSERVED",
                        ),
                        "concept": (
                            template.concept
                            or template.id
                        ),
                        "soft404_similarity": match.get(
                            "soft404_similarity",
                            0.0,
                        ),
                    }

                    findings.append(finding)

                if verbose:
                    print(
                        f"[+] MATCH {template.id} "
                        f"[{template.severity}] "
                        f"{result['matches'][0]['url']}"
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
                    "id",
                    "",
                )
            ),
        )
    )

    duration = perf_counter() - started

    return {
        "findings": findings,
        "load_errors": load_errors,
        "execution_errors": execution_errors,
        "skipped": skipped,
        "not_applicable": not_applicable,
        "cache": http_cache_stats(),
        "stats": {
            "templates": len(templates),
            "executed": len(runnable),
            "not_applicable": len(not_applicable),
            "skipped": len(skipped),
            "matched": len(findings),
            "errors": len(execution_errors),
            "planned_requests": planned_requests,
            "executed_requests": executed_requests,
            "request_budget": selected.template_request_budget,
            "duration": round(duration, 3),
        },
    }
