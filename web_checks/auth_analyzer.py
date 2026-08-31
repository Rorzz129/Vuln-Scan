from __future__ import annotations

import base64
import json
import re

from web_checks.common import (
    WebScanContext,
    ensure_context,
    response_text,
    make_finding,
)

PASSWORD_RE = re.compile(r'<input\b[^>]*type=["\']password["\'][^>]*>', re.I)
JWT_RE = re.compile(r'\beyJ[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]{6,}\b')

def _jwt_header(token: str):
    try:
        header = token.split(".", 1)[0]
        header += "=" * (-len(header) % 4)
        return json.loads(base64.urlsafe_b64decode(header.encode()).decode())
    except Exception:
        return None

def check_auth(value):
    ctx, own = ensure_context(value)
    try:
        if ctx.degraded:
            return []

        html = response_text(ctx.response, limit=1000000)
        lower = html.casefold()
        findings = []

        markers = {
            "login": any(word in lower for word in ("login", "sign in", "signin")),
            "register": any(word in lower for word in ("register", "sign up", "signup")),
            "reset": any(word in lower for word in ("forgot password", "reset password")),
            "password_field": bool(PASSWORD_RE.search(html)),
        }

        if any(markers.values()):
            finding = make_finding(
                "WEB-AUTH-001",
                "Authentication surface detected",
                "INFO",
                "Authentication",
                ctx.url,
                "Observed authentication-related application markers.",
                "Include login, session and recovery flows in the authorized assessment.",
                "HIGH",
            )
            finding["metadata"] = markers
            findings.append(finding)

        headers = []
        for token in JWT_RE.findall(html):
            header = _jwt_header(token)
            if header:
                headers.append(header)

        if headers:
            algs = sorted({str(item.get("alg") or "Unknown") for item in headers})
            finding = make_finding(
                "WEB-AUTH-002",
                "JWT usage detected",
                "HIGH" if "none" in {x.lower() for x in algs} else "INFO",
                "Authentication",
                ctx.url,
                f"JWT-like tokens observed. Algorithms: {', '.join(algs)}.",
                "Validate signature enforcement, expiry, issuer, audience and authorization checks.",
                "MEDIUM",
            )
            finding["metadata"] = {
                "algorithms": algs,
                "token_count": len(headers),
            }
            findings.append(finding)

        return findings
    finally:
        if own:
            ctx.session.close()
