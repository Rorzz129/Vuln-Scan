from __future__ import annotations

import re
from html import unescape
from typing import Any
from urllib.parse import urlsplit

from web_checks.common import create_session, normalize_url, request, response_text
from web_checks.javascript import scan_javascript_technologies

CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

HEADER_SIGNATURES = {
    "server": {
        "apache": "Apache HTTP Server",
        "nginx": "nginx",
        "microsoft-iis": "Microsoft IIS",
        "openresty": "OpenResty",
        "caddy": "Caddy",
        "cloudflare": "Cloudflare",
        "gunicorn": "Gunicorn",
        "uvicorn": "Uvicorn",
        "tomcat": "Apache Tomcat",
        "lighttpd": "lighttpd",
        "litespeed": "LiteSpeed",
        "envoy": "Envoy",
        "traefik": "Traefik",
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express",
        "next.js": "Next.js",
        "nextjs": "Next.js",
        "nuxt": "Nuxt",
        "servlet": "Java Servlet",
        "plesk": "Plesk",
    },
    "x-generator": {
        "wordpress": "WordPress",
        "joomla": "Joomla",
        "drupal": "Drupal",
        "ghost": "Ghost",
    },
    "x-nextjs-cache": {"": "Next.js"},
    "x-vercel-cache": {"": "Vercel"},
    "x-amz-cf-id": {"": "Amazon CloudFront"},
}

COOKIE_SIGNATURES = {
    "phpsessid": "PHP",
    "laravel_session": "Laravel",
    "xsrf-token": "Laravel",
    "csrftoken": "Django",
    "sessionid": "Django",
    "_rails_session": "Ruby on Rails",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "connect.sid": "Express",
    "wordpress_logged_in": "WordPress",
    "wordpress_sec": "WordPress",
    "woocommerce_cart_hash": "WooCommerce",
    "woocommerce_items_in_cart": "WooCommerce",
    "prestashop": "PrestaShop",
}


HTML_SIGNATURES = {
    "PrestaShop": (r"prestashop", r"/themes/[^/]+/assets/", r"PrestaShop-"),
    "WordPress": (r"/(?:wp-content|wp-includes)/", r"\bwp-json\b"),
    "WooCommerce": (r"/wp-content/plugins/woocommerce/", r"\bwc-ajax\b"),
    "Joomla": (r"/media/system/js/", r"/components/com_[a-z0-9_]+/"),
    "Drupal": (r"/sites/(?:default|all)/files/", r"\bdrupalSettings\b"),
    "Laravel": (r"\blaravel_session\b", r'<meta[^>]+name=["\']csrf-token["\']'),
    "Django": (r"\bcsrfmiddlewaretoken\b", r"/static/admin/(?:css|js)/"),
    "Ruby on Rails": (r"\bauthenticity_token\b", r"\brails-ujs\b"),
    "React": (r"\bdata-reactroot\b", r"\b__REACT_DEVTOOLS_GLOBAL_HOOK__\b"),
    "Vue.js": (r"\b__VUE__\b", r"\bdata-v-[a-f0-9]{6,}\b"),
    "Angular": (r'ng-version=["\'][^"\']+["\']', r"<app-root(?:\s|>)"),
    "Next.js": (r"/_next/static/", r"\b__NEXT_DATA__\b"),
    "Nuxt": (r"/_nuxt/", r"\b__NUXT__\b"),
    "Svelte": (r"\bdata-svelte-h\b", r"/_app/immutable/"),
    "Bootstrap": (r"\bbootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)\b",),
    "jQuery": (r"\bjquery(?:[-.]\d+(?:\.\d+){1,3})?(?:\.min)?\.js\b",),
    "Tailwind CSS": (r"\btailwind(?:\.min)?\.css\b", r"cdn\.tailwindcss\.com"),
    "Cloudflare": (r"/cdn-cgi/",),
    "Alpine.js": (r"\balpine(?:\.min)?\.js\b", r"\bx-data(?:=|\s)"),
    "HTMX": (r"\bhtmx(?:\.min)?\.js\b", r"\bhx-(?:get|post|put|delete|trigger)\b"),
}

VERSION_PATTERNS = {
    "PrestaShop": (
        r"PrestaShop(?:\s+|[-.@])([0-9]+(?:\.[0-9]+){1,3})",
        r"prestashop(?:\.min)?[-.@]([0-9]+(?:\.[0-9]+){1,3})",
    ),
    "WordPress": (
        r"WordPress\s*([0-9]+(?:\.[0-9]+){1,3})",
        r"(?:wp-includes|wp-content)/[^\"']+[?&]ver=([0-9]+(?:\.[0-9]+){1,3})",
    ),
    "WooCommerce": (
        r"woocommerce[^\"']+[?&]ver=([0-9]+(?:\.[0-9]+){1,3})",
    ),
    "Angular": (
        r'ng-version=["\']([0-9]+(?:\.[0-9]+){1,3})["\']',
    ),
    "Bootstrap": (
        r"bootstrap(?:\.bundle)?[-.@]([0-9]+(?:\.[0-9]+){1,3})",
    ),
    "jQuery": (
        r"jquery[-.@]([0-9]+(?:\.[0-9]+){1,3})",
    ),
    "Vue.js": (
        r"vue[-.@]([0-9]+(?:\.[0-9]+){1,3})",
    ),
}


def clean_version(version: Any) -> str | None:
    if version is None:
        return None

    value = str(version).strip().lstrip("vV")
    match = re.match(r"^([0-9]+(?:\.[0-9A-Za-z_-]+){0,4})", value)
    return match.group(1) if match else None


def extract_version(value: str) -> str | None:
    if not value:
        return None

    for pattern in (
        r"(?<![A-Za-z0-9])v?([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})(?![A-Za-z0-9])",
        r"\bversion[=/:\s-]+([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})",
    ):
        match = re.search(pattern, value, re.IGNORECASE)
        if match:
            return clean_version(match.group(1))

    return None


def add_technology(
    technologies: dict[str, dict[str, Any]],
    name: str,
    version: str | None,
    evidence: str,
    confidence: str,
    port: int | None,
    source: str = "web",
) -> None:
    name = str(name or "").strip()
    if not name:
        return

    confidence = str(confidence or "LOW").upper()
    if confidence not in CONFIDENCE_ORDER:
        confidence = "LOW"

    version = clean_version(version)
    key = name.casefold()

    current = technologies.get(key)

    if current is None:
        technologies[key] = {
            "name": name,
            "version": version,
            "port": port,
            "source": source,
            "confidence": confidence,
            "evidence": [evidence] if evidence else [],
        }
        return

    if evidence and evidence not in current["evidence"]:
        current["evidence"].append(evidence)

    if version and not current.get("version"):
        current["version"] = version
    elif version and current.get("version") != version:
        alternates = current.setdefault("alternate_versions", [])
        if version not in alternates:
            alternates.append(version)

    if CONFIDENCE_ORDER[confidence] > CONFIDENCE_ORDER.get(current.get("confidence", "LOW"), 0):
        current["confidence"] = confidence

    sources = [item for item in str(current.get("source", "")).split(",") if item]
    if source and source not in sources:
        sources.append(source)
        current["source"] = ",".join(sources)


def detect_web_technologies(
    url: str,
    verbose: bool = True,
) -> list[dict[str, Any]]:
    normalized_url = normalize_url(url)
    session = create_session()

    try:
        response = request(session, "GET", normalized_url)
        parsed = urlsplit(response.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        technologies: dict[str, dict[str, Any]] = {}

        headers = {
            str(key).lower(): str(value)
            for key, value in response.headers.items()
        }

        for header, signatures in HEADER_SIGNATURES.items():
            value = headers.get(header)
            if value is None:
                continue

            lowered = value.lower()

            for signature, name in signatures.items():
                if signature and signature not in lowered:
                    continue

                add_technology(
                    technologies,
                    name,
                    extract_version(value),
                    f"{header}: {value}",
                    "HIGH",
                    port,
                    "header",
                )

        cookie_names = {str(cookie.name).lower() for cookie in response.cookies}
        raw_cookie = headers.get("set-cookie", "").lower()

        for signature, name in COOKIE_SIGNATURES.items():
            if any(
                cookie_name == signature or cookie_name.startswith(signature)
                for cookie_name in cookie_names
            ) or signature in raw_cookie:
                add_technology(
                    technologies,
                    name,
                    None,
                    f"Cookie detected: {signature}",
                    "MEDIUM",
                    port,
                    "cookie",
                )

        content_type = headers.get("content-type", "").lower()

        if "text/html" in content_type or not content_type:
            html = unescape(response_text(response))

            meta_matches = re.findall(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                html,
                re.IGNORECASE,
            )

            for value in meta_matches:
                for technology in ("WordPress", "Joomla", "Drupal", "Ghost", "PrestaShop"):
                    if technology.casefold() in value.casefold():
                        add_technology(
                            technologies,
                            technology,
                            extract_version(value),
                            f"Meta generator: {value}",
                            "HIGH",
                            port,
                            "meta",
                        )

            for name, patterns in HTML_SIGNATURES.items():
                matched = None

                for pattern in patterns:
                    matched = re.search(pattern, html, re.IGNORECASE)
                    if matched:
                        break

                if not matched:
                    continue

                version = None
                for version_pattern in VERSION_PATTERNS.get(name, ()):
                    version_match = re.search(version_pattern, html, re.IGNORECASE)
                    if version_match:
                        version = clean_version(version_match.group(1))
                        break

                evidence = matched.group(0)
                if len(evidence) > 160:
                    evidence = evidence[:157] + "..."

                add_technology(
                    technologies,
                    name,
                    version,
                    f"HTML signature: {evidence}",
                    "HIGH" if version else "MEDIUM",
                    port,
                    "html",
                )

            javascript_results = scan_javascript_technologies(
                session=session,
                html=html,
                base_url=response.url,
                port=port,
            )

            for technology in javascript_results:
                evidence = technology.get("evidence") or ["JavaScript detection"]

                for item in evidence:
                    add_technology(
                        technologies,
                        str(technology.get("name") or "Unknown"),
                        technology.get("version"),
                        str(item),
                        str(technology.get("confidence") or "MEDIUM"),
                        technology.get("port", port),
                        str(technology.get("source") or "javascript"),
                    )

    finally:
        session.close()

    results = sorted(
        technologies.values(),
        key=lambda item: (
            -CONFIDENCE_ORDER.get(str(item.get("confidence", "LOW")).upper(), 0),
            str(item.get("name", "")).casefold(),
        ),
    )

    if verbose:
        print(f"[+] Web technologies detected: {len(results)}")
        for technology in results:
            print(
                f"[+] {technology['name']} "
                f"{technology.get('version') or 'Unknown'} "
                f"({technology.get('confidence', 'LOW')})"
            )

    return results
