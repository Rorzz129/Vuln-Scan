from __future__ import annotations

from typing import Any

from web_checks.common import (
    WebScanContext,
    ensure_context,
    make_finding,
    cached_request,
)

TEST_ORIGIN = "https://vulnscope.invalid"
NULL_ORIGIN = "null"

SEVERITY_ORDER = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

def _cors(
    response: Any,
) -> tuple[str, bool]:
    return (
        str(
            response.headers.get(
                "Access-Control-Allow-Origin",
                "",
            )
        ).strip(),
        str(
            response.headers.get(
                "Access-Control-Allow-Credentials",
                "",
            )
        ).strip().lower()
        == "true",
    )

def _response_sensitivity(
    response: Any,
) -> str:
    content_type = str(
        response.headers.get(
            "Content-Type",
            "",
        )
    ).lower()

    try:
        body = (
            response.text[
                :20000
            ].lower()
        )
    except Exception:
        body = ""

    markers = (
        '"email"',
        '"username"',
        '"account"',
        '"profile"',
        '"token"',
        '"address"',
        '"phone"',
        "my account",
        "logout",
    )

    if (
        "application/json"
        in content_type
        and any(
            marker in body
            for marker in markers
        )
    ):
        return (
            "POTENTIALLY_SENSITIVE"
        )

    return "UNKNOWN"

def _worst(
    current: str,
    candidate: str,
) -> str:
    return (
        candidate
        if SEVERITY_ORDER.get(
            candidate,
            0,
        )
        > SEVERITY_ORDER.get(
            current,
            0,
        )
        else current
    )

def check_cors(
    value: str | WebScanContext,
) -> list[dict[str, Any]]:
    ctx, own = ensure_context(
        value
    )

    try:
        if ctx.degraded:
            return []

        baseline = ctx.response

        arbitrary = cached_request(
            ctx.session,
            "GET",
            ctx.url,
            headers={
                "Origin": TEST_ORIGIN,
            },
        )

        null_response = cached_request(
            ctx.session,
            "GET",
            ctx.url,
            headers={
                "Origin": NULL_ORIGIN,
            },
        )

        (
            arbitrary_origin,
            arbitrary_creds,
        ) = _cors(
            arbitrary
        )

        (
            null_origin,
            null_creds,
        ) = _cors(
            null_response
        )

        (
            baseline_origin,
            _,
        ) = _cors(
            baseline
        )

        sensitivity = (
            _response_sensitivity(
                arbitrary
            )
        )

        issues = []
        severity = "INFO"
        exploitability = (
            "UNCONFIRMED"
        )

        if (
            arbitrary_origin
            == TEST_ORIGIN
        ):
            issue_severity = (
                "HIGH"
                if arbitrary_creds
                else "MEDIUM"
                if (
                    sensitivity
                    == "POTENTIALLY_SENSITIVE"
                )
                else "LOW"
            )

            severity = _worst(
                severity,
                issue_severity,
            )

            if arbitrary_creds:
                exploitability = "LIKELY"
            elif (
                sensitivity
                == "POTENTIALLY_SENSITIVE"
            ):
                exploitability = "POSSIBLE"

            issues.append(
                {
                    "type": "ARBITRARY_ORIGIN_REFLECTION",
                    "severity": issue_severity,
                    "detail": (
                        f"{TEST_ORIGIN} reflected; "
                        f"credentials={'yes' if arbitrary_creds else 'no'}"
                    ),
                }
            )

        if arbitrary_origin == "*":
            severity = _worst(
                severity,
                "LOW",
            )

            issues.append(
                {
                    "type": "WILDCARD_ORIGIN",
                    "severity": "LOW",
                    "detail": (
                        "Access-Control-Allow-Origin: *"
                    ),
                }
            )

        if null_origin == "null":
            issue_severity = (
                "HIGH"
                if null_creds
                else "MEDIUM"
            )

            severity = _worst(
                severity,
                issue_severity,
            )

            if null_creds:
                exploitability = "LIKELY"
            elif (
                exploitability
                == "UNCONFIRMED"
            ):
                exploitability = "POSSIBLE"

            issues.append(
                {
                    "type": "NULL_ORIGIN_ACCEPTED",
                    "severity": issue_severity,
                    "detail": (
                        "Origin: null accepted"
                        + (
                            " with credentials"
                            if null_creds
                            else ""
                        )
                    ),
                }
            )

        if (
            arbitrary_origin
            == TEST_ORIGIN
            and baseline_origin
            != arbitrary_origin
        ):
            vary = {
                item.strip().lower()
                for item in str(
                    arbitrary.headers.get(
                        "Vary",
                        "",
                    )
                ).split(",")
                if item.strip()
            }

            if "origin" not in vary:
                severity = _worst(
                    severity,
                    "LOW",
                )

                issues.append(
                    {
                        "type": "MISSING_VARY_ORIGIN",
                        "severity": "LOW",
                        "detail": (
                            "Dynamic ACAO response missing Vary: Origin"
                        ),
                    }
                )

        if not issues:
            return []

        evidence = "; ".join(
            issue["detail"]
            for issue in issues
        )

        finding = make_finding(
            "WEB-CORS-SUMMARY",
            "CORS policy weaknesses detected",
            severity,
            "CORS",
            arbitrary.url,
            (
                f"{evidence}. "
                f"Response sensitivity={sensitivity}; "
                f"exploitability={exploitability}."
            ),
            (
                "Use an explicit trusted-origin allowlist, avoid trusting null origins, "
                "only allow credentials where necessary, and send Vary: Origin for dynamic policies."
            ),
            "HIGH",
        )

        finding["metadata"] = {
            "issues": issues,
            "arbitrary_origin": arbitrary_origin,
            "arbitrary_credentials": arbitrary_creds,
            "null_origin": null_origin,
            "null_credentials": null_creds,
            "response_sensitivity": sensitivity,
            "exploitability": exploitability,
        }

        return [finding]

    finally:
        if own:
            ctx.session.close()
