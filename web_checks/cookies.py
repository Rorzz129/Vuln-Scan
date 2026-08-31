from __future__ import annotations
from http.cookies import SimpleCookie
from typing import Any

from web_checks.common import (
    WebScanContext,
    ensure_context,
    make_finding,
)

SESSION_HINTS = (
    "session",
    "sess",
    "auth",
    "token",
    "jwt",
    "sid",
    "login",
    "prestashop",
)

TRACKING_HINTS = (
    "_ga",
    "_gid",
    "_fbp",
    "fbp",
    "analytics",
    "pixel",
)

def _set_cookie_headers(response: Any) -> list[str]:
    raw = getattr(response, "raw", None)
    headers = getattr(raw, "headers", None)

    if headers and hasattr(headers, "getlist"):
        values = headers.getlist("Set-Cookie")
        if values:
            return [
                str(value)
                for value in values
                if value
            ]

    value = response.headers.get("Set-Cookie")
    return [value] if value else []

def _parse(
    header: str,
) -> tuple[str, dict[str, str | bool]]:
    cookie = SimpleCookie()
    name = "unknown"

    try:
        cookie.load(header)
        if cookie:
            name = next(iter(cookie.keys()))
    except Exception:
        pass

    attrs: dict[str, str | bool] = {}

    for part in header.split(";")[1:]:
        part = part.strip()
        if not part:
            continue

        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            attrs[part.lower()] = True

    return name, attrs

def _sensitivity(name: str) -> str:
    lowered = name.casefold()

    if any(hint in lowered for hint in TRACKING_HINTS):
        return "LOW"

    if any(hint in lowered for hint in SESSION_HINTS):
        return "HIGH"

    return "MEDIUM"

def _add_metadata(
    finding: dict[str, Any],
    *,
    name: str,
    sensitivity: str,
) -> None:
    finding["metadata"] = {
        "cookie_name": name,
        "cookie_sensitivity": sensitivity,
    }

def check_cookies(
    value: str | WebScanContext,
) -> list[dict[str, Any]]:
    ctx, own = ensure_context(value)
    findings: list[dict[str, Any]] = []

    try:
        if ctx.degraded:
            return findings

        response = ctx.response

        for header in _set_cookie_headers(response):
            name, attrs = _parse(header)
            sensitivity = _sensitivity(name)

            secure = "secure" in attrs
            httponly = "httponly" in attrs
            samesite = str(
                attrs.get(
                    "samesite",
                    "",
                )
            ).lower()

            if (
                response.url.startswith("https://")
                and not secure
            ):
                severity = (
                    "MEDIUM"
                    if sensitivity == "HIGH"
                    else "LOW"
                )

                finding = make_finding(
                    "WEB-COOKIE-001",
                    f'Cookie "{name}" missing Secure attribute',
                    severity,
                    "Cookies",
                    response.url,
                    f'Cookie "{name}" is set over HTTPS without Secure.',
                    "Set Secure on cookies transmitted over HTTPS.",
                    "HIGH",
                )
                _add_metadata(
                    finding,
                    name=name,
                    sensitivity=sensitivity,
                )
                findings.append(finding)

            if not httponly:
                severity = (
                    "MEDIUM"
                    if sensitivity == "HIGH"
                    else "INFO"
                    if sensitivity == "LOW"
                    else "LOW"
                )

                finding = make_finding(
                    "WEB-COOKIE-002",
                    f'Cookie "{name}" missing HttpOnly attribute',
                    severity,
                    "Cookies",
                    response.url,
                    f'Cookie "{name}" is not marked HttpOnly.',
                    "Set HttpOnly on cookies that do not require JavaScript access.",
                    "MEDIUM",
                )
                _add_metadata(
                    finding,
                    name=name,
                    sensitivity=sensitivity,
                )
                findings.append(finding)

            if not samesite:
                severity = (
                    "LOW"
                    if sensitivity == "HIGH"
                    else "INFO"
                )

                finding = make_finding(
                    "WEB-COOKIE-003",
                    f'Cookie "{name}" missing SameSite attribute',
                    severity,
                    "Cookies",
                    response.url,
                    f'Cookie "{name}" has no explicit SameSite attribute.',
                    "Set SameSite=Lax or SameSite=Strict where compatible with application behavior.",
                    "MEDIUM",
                )
                _add_metadata(
                    finding,
                    name=name,
                    sensitivity=sensitivity,
                )
                findings.append(finding)

            if samesite == "none" and not secure:
                finding = make_finding(
                    "WEB-COOKIE-004",
                    f'Cookie "{name}" uses SameSite=None without Secure',
                    "MEDIUM",
                    "Cookies",
                    response.url,
                    f'Cookie "{name}" uses SameSite=None but is not marked Secure.',
                    "Cookies using SameSite=None should also use Secure.",
                    "HIGH",
                )
                _add_metadata(
                    finding,
                    name=name,
                    sensitivity=sensitivity,
                )
                findings.append(finding)

        return findings

    finally:
        if own:
            ctx.session.close()
