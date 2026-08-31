from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit
import socket
import ssl

from web_checks.common import (
    WebScanContext,
    ensure_context,
    make_finding,
    create_session,
    cached_request,
)

def _http_url(
    https_url: str,
) -> str:
    parsed = urlsplit(
        https_url
    )

    host = (
        parsed.hostname
        or ""
    )
    netloc = host

    if (
        parsed.port
        and parsed.port
        not in {443, 80}
    ):
        netloc = (
            f"{host}:{parsed.port}"
        )

    return urlunsplit(
        (
            "http",
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )

def _check_http_redirect(
    ctx: WebScanContext,
) -> list[dict[str, Any]]:
    if not ctx.url.lower().startswith(
        "https://"
    ):
        return []

    session = create_session()

    try:
        response = cached_request(
            session,
            "HEAD",
            _http_url(
                ctx.url
            ),
            allow_redirects=False,
            timeout=(2.5, 4.0),
        )
    except Exception:
        return []
    finally:
        session.close()

    location = str(
        response.headers.get(
            "Location",
            "",
        )
    )

    if (
        response.status_code
        in {301, 302, 307, 308}
        and location.lower().startswith(
            "https://"
        )
    ):
        return []

    return [
        make_finding(
            "WEB-TRANSPORT-001",
            "HTTP does not clearly redirect to HTTPS",
            "LOW",
            "Transport Security",
            _http_url(
                ctx.url
            ),
            (
                f"HTTP response was {response.status_code}; "
                f"Location={location or 'not present'}."
            ),
            "Redirect HTTP traffic to the canonical HTTPS origin.",
            "MEDIUM",
        )
    ]

def _certificate_info(
    hostname: str,
    port: int,
) -> dict[str, Any]:
    context = (
        ssl.create_default_context()
    )

    with socket.create_connection(
        (hostname, port),
        timeout=4.0,
    ) as raw:
        with context.wrap_socket(
            raw,
            server_hostname=hostname,
        ) as sock:
            certificate = (
                sock.getpeercert()
            )
            tls_version = (
                sock.version()
            )
            cipher = (
                sock.cipher()
            )

    expires = certificate.get(
        "notAfter"
    )
    days_left = None

    if expires:
        expiry_ts = (
            ssl.cert_time_to_seconds(
                expires
            )
        )
        expiry = (
            datetime.fromtimestamp(
                expiry_ts,
                tz=timezone.utc,
            )
        )
        days_left = (
            expiry
            - datetime.now(
                timezone.utc
            )
        ).total_seconds() / 86400

    return {
        "certificate": certificate,
        "tls_version": tls_version,
        "cipher": (
            cipher[0]
            if cipher
            else None
        ),
        "days_left": days_left,
        "expires": expires,
    }

def _check_tls(
    ctx: WebScanContext,
) -> list[dict[str, Any]]:
    parsed = urlsplit(
        ctx.url
    )

    if (
        parsed.scheme != "https"
        or not parsed.hostname
    ):
        return []

    port = (
        parsed.port
        or 443
    )

    try:
        info = (
            _certificate_info(
                parsed.hostname,
                port,
            )
        )
    except Exception:
        return []

    findings = []
    days_left = info.get(
        "days_left"
    )

    if days_left is not None:
        if days_left < 0:
            severity = "HIGH"
            title = (
                "TLS certificate expired"
            )
        elif days_left < 14:
            severity = "MEDIUM"
            title = (
                "TLS certificate expires very soon"
            )
        elif days_left < 30:
            severity = "LOW"
            title = (
                "TLS certificate expires soon"
            )
        else:
            severity = None
            title = ""

        if severity:
            findings.append(
                make_finding(
                    "WEB-TLS-001",
                    title,
                    severity,
                    "Transport Security",
                    ctx.url,
                    (
                        f"Certificate expiry={info.get('expires')}; "
                        f"approximately {days_left:.1f} day(s) remaining."
                    ),
                    "Renew and deploy the certificate before expiry.",
                    "HIGH",
                )
            )

    tls_version = str(
        info.get(
            "tls_version"
        )
        or ""
    )

    if tls_version in {
        "TLSv1",
        "TLSv1.1",
    }:
        findings.append(
            make_finding(
                "WEB-TLS-002",
                "Legacy TLS protocol negotiated",
                "MEDIUM",
                "Transport Security",
                ctx.url,
                (
                    f"Negotiated protocol: {tls_version}."
                ),
                "Disable legacy TLS versions and prefer TLS 1.2/1.3.",
                "HIGH",
            )
        )

    return findings

def check_transport(
    value: str | WebScanContext,
) -> list[dict[str, Any]]:
    ctx, own = ensure_context(
        value
    )

    try:
        findings = []
        findings.extend(
            _check_http_redirect(
                ctx
            )
        )
        findings.extend(
            _check_tls(
                ctx
            )
        )
        return findings

    finally:
        if own:
            ctx.session.close()
