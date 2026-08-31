from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlsplit, urldefrag
import re

from web_checks.common import create_session, cached_request, response_text

LINK_RE = re.compile(r'(?:href|src|action)=["\']([^"\'#]+)["\']', re.I)
FORM_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.I | re.S)
INPUT_RE = re.compile(r'<(?:input|textarea|select)\b[^>]*name=["\']([^"\']+)["\']', re.I)
METHOD_RE = re.compile(r'method=["\']([^"\']+)["\']', re.I)
ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.I)

def _origin(url: str):
    p = urlsplit(url)
    return (
        p.scheme.lower(),
        (p.hostname or "").lower(),
        p.port or (443 if p.scheme == "https" else 80),
    )

def _normalize(base: str, raw: str):
    raw = str(raw or "").strip()
    if not raw or raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    url = urljoin(base, raw)
    url, _ = urldefrag(url)
    if _origin(base) != _origin(url):
        return None
    return url

def crawl(start_url: str, max_pages: int = 30, max_depth: int = 2):
    session = create_session()
    queue = deque([(start_url, 0)])
    visited = set()
    pages = []
    forms = []
    parameters = set()

    try:
        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            try:
                response = cached_request(
                    session,
                    "GET",
                    url,
                    timeout=(2.5, 5.0),
                    allow_redirects=True,
                )
            except Exception as exc:
                pages.append({
                    "url": url,
                    "status": None,
                    "depth": depth,
                    "error": str(exc),
                })
                continue

            content_type = str(response.headers.get("Content-Type", "")).lower()
            html = response_text(response, limit=700000) if "html" in content_type else ""

            page = {
                "url": response.url,
                "status": response.status_code,
                "depth": depth,
                "content_type": content_type,
                "links": [],
            }

            for attrs, body in FORM_RE.findall(html):
                action_match = ACTION_RE.search(attrs)
                method_match = METHOD_RE.search(attrs)
                action = _normalize(
                    response.url,
                    action_match.group(1) if action_match else response.url,
                ) or response.url
                method = method_match.group(1).upper() if method_match else "GET"
                names = []
                for name in INPUT_RE.findall(body):
                    if name not in names:
                        names.append(name)
                        parameters.add(name)
                forms.append({
                    "action": action,
                    "method": method,
                    "parameters": names,
                })

            if depth < max_depth:
                for raw in LINK_RE.findall(html):
                    candidate = _normalize(response.url, raw)
                    if not candidate:
                        continue
                    if candidate not in page["links"]:
                        page["links"].append(candidate)
                    parsed = urlsplit(candidate)
                    for part in parsed.query.split("&"):
                        if part:
                            parameters.add(part.split("=", 1)[0])
                    if candidate not in visited:
                        queue.append((candidate, depth + 1))

            pages.append(page)

        return {
            "pages": pages,
            "forms": forms,
            "parameters": sorted(parameters),
            "visited": len(visited),
            "max_pages": max_pages,
            "max_depth": max_depth,
        }
    finally:
        session.close()
