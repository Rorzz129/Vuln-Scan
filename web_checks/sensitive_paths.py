from __future__ import annotations

from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
from typing import Any
from urllib.parse import urljoin

from web_checks.accuracy import (
    build_soft404_baselines,
    looks_like_soft404,
    content_type_matches,
)
from web_checks.common import (
    WebScanContext,
    ensure_context,
    create_session,
    cached_request,
    make_finding,
    response_text,
)

PATH_RULES = {
    "/.env": {
        "id": "WEB-PATH-001",
        "title": "Potential environment file exposure",
        "severity": "HIGH",
        "signatures": (
            "APP_KEY=",
            "DB_PASSWORD=",
            "DATABASE_URL=",
            "SECRET_KEY=",
        ),
        "mode": "any",
        "types": (
            "text/plain",
            "application/octet-stream",
        ),
        "recommendation": (
            "Remove environment files from the public web root "
            "and deny HTTP access."
        ),
        "verification": "CONFIRMED",
    },
    "/.git/HEAD": {
        "id": "WEB-PATH-002",
        "title": "Potential Git repository exposure",
        "severity": "HIGH",
        "signatures": (
            "ref: refs/heads/",
            "ref: refs/",
        ),
        "mode": "any",
        "types": (
            "text/plain",
            "application/octet-stream",
        ),
        "recommendation": (
            "Remove .git metadata from the public web root "
            "and deny HTTP access."
        ),
        "verification": "CONFIRMED",
    },
    "/phpinfo.php": {
        "id": "WEB-PATH-003",
        "title": "PHP information page exposed",
        "severity": "MEDIUM",
        "signatures": (
            "phpinfo()",
            "PHP Version",
        ),
        "mode": "all",
        "types": (
            "text/html",
        ),
        "recommendation": (
            "Remove publicly accessible phpinfo pages."
        ),
        "verification": "CONFIRMED",
    },
    "/server-status": {
        "id": "WEB-PATH-004",
        "title": "Server status page exposed",
        "severity": "MEDIUM",
        "signatures": (
            "Apache Server Status",
            "Server Version:",
        ),
        "mode": "any",
        "types": (
            "text/html",
            "text/plain",
        ),
        "recommendation": (
            "Restrict server-status to authorized administrators."
        ),
        "verification": "CONFIRMED",
    },
    "/swagger.json": {
        "id": "WEB-PATH-005",
        "title": "Swagger API specification exposed",
        "severity": "INFO",
        "signatures": (
            '"swagger"',
            '"paths"',
        ),
        "mode": "all",
        "types": (
            "application/json",
            "text/json",
        ),
        "recommendation": (
            "Confirm public API documentation is intentional."
        ),
        "verification": "OBSERVED",
    },
    "/openapi.json": {
        "id": "WEB-PATH-006",
        "title": "OpenAPI specification exposed",
        "severity": "INFO",
        "signatures": (
            '"openapi"',
            '"paths"',
        ),
        "mode": "all",
        "types": (
            "application/json",
            "text/json",
        ),
        "recommendation": (
            "Confirm public API documentation is intentional."
        ),
        "verification": "OBSERVED",
    },
    "/api-docs": {
        "id": "WEB-PATH-007",
        "title": "API documentation endpoint discovered",
        "severity": "INFO",
        "signatures": (
            "swagger",
            "openapi",
            "api documentation",
        ),
        "mode": "any",
        "types": (
            "text/html",
            "application/json",
        ),
        "recommendation": (
            "Review whether the documentation should be publicly accessible."
        ),
        "verification": "OBSERVED",
    },
    "/robots.txt": {
        "id": "WEB-PATH-008",
        "title": "robots.txt discovered",
        "severity": "INFO",
        "signatures": (
            "User-agent:",
        ),
        "mode": "all",
        "types": (
            "text/plain",
        ),
        "recommendation": (
            "Review robots.txt for unnecessarily exposed application paths."
        ),
        "verification": "OBSERVED",
    },
    "/.well-known/security.txt": {
        "id": "WEB-PATH-009",
        "title": "security.txt discovered",
        "severity": "INFO",
        "signatures": (
            "Contact:",
        ),
        "mode": "all",
        "types": (
            "text/plain",
        ),
        "recommendation": (
            "Keep security contact information current."
        ),
        "verification": "OBSERVED",
    },
    "/package.json": {
        "id": "WEB-PATH-010",
        "title": "package.json exposed",
        "severity": "LOW",
        "signatures": (
            '"dependencies"',
            '"name"',
        ),
        "mode": "all",
        "types": (
            "application/json",
            "text/plain",
        ),
        "recommendation": (
            "Avoid exposing application package manifests unless intentional."
        ),
        "verification": "CONFIRMED",
    },
}

def _matches(
    body: str,
    signatures: tuple[str, ...],
    mode: str,
) -> bool:
    lower = body.lower()

    checks = [
        signature.lower()
        in lower
        for signature
        in signatures
    ]

    return (
        all(checks)
        if mode == "all"
        else any(checks)
    )

def _fetch(
    url: str,
):
    session = create_session()

    try:
        return cached_request(
            session,
            "GET",
            url,
            timeout=(2.5, 4.5),
            allow_redirects=True,
        )
    finally:
        session.close()

def check_sensitive_paths(
    value: str | WebScanContext,
) -> list[dict[str, Any]]:
    ctx, own = ensure_context(
        value
    )
    findings = []

    try:
        if ctx.degraded:
            return findings

        baselines = (
            build_soft404_baselines(
                ctx,
                count=2,
            )
        )

        targets = {
            urljoin(
                ctx.origin + "/",
                path.lstrip("/"),
            ): (
                path,
                rule,
            )
            for path, rule
            in PATH_RULES.items()
        }

        with ThreadPoolExecutor(
            max_workers=min(
                6,
                len(targets),
            )
        ) as pool:
            futures = {
                pool.submit(
                    _fetch,
                    target,
                ): target
                for target
                in targets
            }

            for future in as_completed(
                futures
            ):
                target = futures[
                    future
                ]
                path, rule = (
                    targets[target]
                )

                try:
                    response = (
                        future.result()
                    )
                except Exception:
                    continue

                if (
                    response.status_code
                    not in {
                        200,
                        206,
                    }
                ):
                    continue

                soft404, similarity = (
                    looks_like_soft404(
                        response,
                        baselines,
                        threshold=0.90,
                    )
                )

                if soft404:
                    continue

                if not content_type_matches(
                    response,
                    list(
                        rule["types"]
                    ),
                ):
                    continue

                body = response_text(
                    response,
                    limit=75000,
                )

                if not _matches(
                    body,
                    rule[
                        "signatures"
                    ],
                    rule["mode"],
                ):
                    continue

                finding = make_finding(
                    rule["id"],
                    rule["title"],
                    rule[
                        "severity"
                    ],
                    "Sensitive Paths",
                    response.url,
                    (
                        f"{response.url} returned HTTP "
                        f"{response.status_code}; "
                        f"signature matched; "
                        f"soft-404 similarity={similarity:.2f}."
                    ),
                    rule[
                        "recommendation"
                    ],
                    "HIGH",
                )

                finding[
                    "verification"
                ] = rule[
                    "verification"
                ]

                finding[
                    "metadata"
                ] = {
                    "requested_path": path,
                    "content_type": (
                        response.headers.get(
                            "Content-Type",
                            "",
                        )
                    ),
                    "soft404_similarity": round(
                        similarity,
                        3,
                    ),
                }

                findings.append(
                    finding
                )

        return findings

    finally:
        if own:
            ctx.session.close()
