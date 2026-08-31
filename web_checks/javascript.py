from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit

MAX_SCRIPTS = 20
MAX_SCRIPT_SIZE = 1_500_000
REQUEST_TIMEOUT = 8

TECHNOLOGY_PATTERNS = {
    "Vue.js": (
        r"\bVue\.version\s*=\s*[\"']([^\"']+)[\"']",
        r"\b__VUE__\b",
        r"\bcreateApp\s*\(",
    ),
    "Nuxt": (
        r"\b__NUXT__\b",
        r"\b__NUXT_DATA__\b",
        r"\bdefineNuxtPlugin\b",
    ),
    "React": (
        r"\bReact\.version\s*=\s*[\"']([^\"']+)[\"']",
        r"\b__REACT_DEVTOOLS_GLOBAL_HOOK__\b",
        r"\bcreateRoot\s*\(",
    ),
    "Next.js": (
        r"\b__NEXT_DATA__\b",
        r"\bnext/navigation\b",
        r"/_next/static/",
    ),
    "Angular": (
        r"\bVERSION\s*=\s*new\s+Version\([\"']([^\"']+)[\"']\)",
        r"\bɵɵdefineComponent\b",
        r"\bplatformBrowserDynamic\b",
    ),
    "jQuery": (
        r"\bjQuery\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bjQuery\.fn\.jquery\b",
    ),
    "Axios": (
        r"\baxios\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\baxios\.VERSION\b",
    ),
    "Bootstrap": (
        r"\bBootstrap\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bbootstrap\.Modal\b",
    ),
    "Lodash": (
        r"\b_.templateSettings\b",
        r"\b_.VERSION\b",
    ),
    "Moment.js": (
        r"\bmoment\.utc\b",
        r"\bmoment\.version\b",
    ),
    "Webpack": (
        r"\b__webpack_require__\b",
        r"\bwebpackChunk[a-zA-Z0-9_$]*\b",
    ),
    "Svelte": (
        r"\bSvelteComponent\b",
        r"\bdata-svelte-h\b",
    ),
    "Alpine.js": (
        r"\bAlpine\.version\b",
        r"\bAlpine\.start\s*\(",
    ),
    "HTMX": (
        r"\bhtmx\.version\b",
        r"\bhtmx\.ajax\b",
    ),
}

VERSION_PATTERNS = {
    "Vue.js": (
        r"\bVue\.version\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\bvue@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ),
    "React": (
        r"\bReact\.version\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\breact@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ),
    "Angular": (
        r"\bVERSION\s*=\s*new\s+Version\([\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']\)",
    ),
    "jQuery": (
        r"\bjQuery\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bjquery[-.@]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ),
    "Axios": (
        r"\baxios\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ),
    "Bootstrap": (
        r"\bBootstrap\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ),
    "Alpine.js": (
        r"\balpine(?:js)?[-.@]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ),
    "HTMX": (
        r"\bhtmx[-.@]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ),
}


def clean_version(version: Any) -> str | None:
    if version is None:
        return None

    value = str(version).strip().lstrip("vV")
    match = re.match(r"^([0-9]+(?:\.[0-9A-Za-z_-]+){1,4})", value)
    return match.group(1) if match else None


def extract_script_sources(html: str, base_url: str) -> list[str]:
    sources = re.findall(
        r"<script[^>]+src=[\"']([^\"']+)[\"']",
        html,
        re.IGNORECASE,
    )

    results: list[str] = []

    for source in sources:
        full_url = urljoin(base_url, source.strip())
        parsed = urlsplit(full_url)

        if parsed.scheme not in {"http", "https"}:
            continue

        if full_url not in results:
            results.append(full_url)

        if len(results) >= MAX_SCRIPTS:
            break

    return results


def extract_version(
    technology: str,
    content: str,
    script_url: str,
) -> str | None:
    searchable = f"{script_url}\n{content}"

    for pattern in VERSION_PATTERNS.get(technology, ()):
        match = re.search(pattern, searchable, re.IGNORECASE)
        if match:
            return clean_version(match.group(1))

    return None


def detect_source_map(content: str, script_url: str) -> str | None:
    for pattern in (
        r"//#\s*sourceMappingURL\s*=\s*([^\s]+)",
        r"/\*#\s*sourceMappingURL\s*=\s*([^\s*]+)",
    ):
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return urljoin(script_url, match.group(1).strip())

    return None


def analyze_script(
    script_url: str,
    content: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for technology, patterns in TECHNOLOGY_PATTERNS.items():
        match = None

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                break

        if not match:
            continue

        evidence = match.group(0)
        if len(evidence) > 160:
            evidence = evidence[:157] + "..."

        version = extract_version(technology, content, script_url)

        results.append({
            "name": technology,
            "version": version,
            "source": "javascript",
            "confidence": "HIGH" if version else "MEDIUM",
            "evidence": [
                f"JavaScript: {script_url}",
                f"Signature: {evidence}",
            ],
        })

    source_map = detect_source_map(content, script_url)
    if source_map:
        results.append({
            "name": "JavaScript Source Map",
            "version": None,
            "source": "javascript",
            "confidence": "HIGH",
            "evidence": [f"Source map referenced: {source_map}"],
            "metadata": {"source_map_url": source_map},
        })

    return results


def merge_javascript_results(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    confidence_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

    for result in results:
        name = str(result.get("name") or "").strip()
        if not name:
            continue

        key = name.casefold()
        current = merged.get(key)

        if current is None:
            current = result.copy()
            current["evidence"] = list(result.get("evidence") or [])
            merged[key] = current
            continue

        new_version = result.get("version")
        if new_version and not current.get("version"):
            current["version"] = new_version
        elif new_version and current.get("version") != new_version:
            versions = current.setdefault("alternate_versions", [])
            if new_version not in versions:
                versions.append(new_version)

        old_conf = str(current.get("confidence") or "LOW").upper()
        new_conf = str(result.get("confidence") or "LOW").upper()

        if confidence_order.get(new_conf, 0) > confidence_order.get(old_conf, 0):
            current["confidence"] = new_conf

        evidence = current.setdefault("evidence", [])
        for item in result.get("evidence") or []:
            if item not in evidence:
                evidence.append(item)

        if result.get("metadata"):
            current.setdefault("metadata", {}).update(result["metadata"])

    return list(merged.values())


def scan_javascript_technologies(
    session: Any,
    html: str,
    base_url: str,
    port: int | None = None,
) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []

    for script_url in extract_script_sources(html, base_url):
        try:
            response = session.get(
                script_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={
                    "Accept": "application/javascript,text/javascript,*/*;q=0.8",
                },
            )
        except Exception:
            continue

        if response.status_code >= 400:
            continue

        content_type = str(response.headers.get("Content-Type", "")).lower()
        if content_type and not any(
            marker in content_type
            for marker in (
                "javascript",
                "ecmascript",
                "text/plain",
                "application/octet-stream",
            )
        ):
            continue

        content = response.text[:MAX_SCRIPT_SIZE]

        for detection in analyze_script(script_url, content):
            detection.setdefault("port", port)
            detections.append(detection)

    return merge_javascript_results(detections)
