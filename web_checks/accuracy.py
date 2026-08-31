from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from hashlib import sha256
from typing import Any
from urllib.parse import urljoin, urlsplit
import re
import secrets

from web_checks.common import (
    WebScanContext,
    create_session,
    cached_request,
    response_text,
)

TITLE_RE = re.compile(
    r"<title[^>]*>(.*?)</title>",
    re.I | re.S,
)

DYNAMIC_PATTERNS = (
    re.compile(r"\b[0-9a-f]{16,}\b", re.I),
    re.compile(r"\b\d{10,}\b"),
    re.compile(r"__vulnscope_[0-9a-f]+", re.I),
)

@dataclass(slots=True)
class ResponseFingerprint:
    status_code: int
    final_url: str
    content_type: str
    length: int
    title: str
    normalized: str
    digest: str

def _normalize_body(value: str) -> str:
    text = str(value or "")
    text = re.sub(
        r"\s+",
        " ",
        text,
    ).strip()

    for pattern in DYNAMIC_PATTERNS:
        text = pattern.sub(
            "<dynamic>",
            text,
        )

    return text[:50000]

def fingerprint_response(
    response: Any,
) -> ResponseFingerprint:
    text = response_text(
        response,
        limit=50000,
    )

    normalized = _normalize_body(
        text
    )

    title_match = TITLE_RE.search(
        text
    )

    title = (
        re.sub(
            r"\s+",
            " ",
            title_match.group(1),
        ).strip()
        if title_match
        else ""
    )

    return ResponseFingerprint(
        status_code=int(
            response.status_code
        ),
        final_url=str(
            response.url
        ),
        content_type=str(
            response.headers.get(
                "Content-Type",
                "",
            )
        ).split(
            ";",
            1,
        )[0].strip().lower(),
        length=len(
            response.content
            or b""
        ),
        title=title,
        normalized=normalized,
        digest=sha256(
            normalized.encode(
                "utf-8",
                errors="ignore",
            )
        ).hexdigest(),
    )

def similarity(
    left: ResponseFingerprint,
    right: ResponseFingerprint,
) -> float:
    if (
        left.digest
        and left.digest
        == right.digest
    ):
        return 1.0

    if (
        not left.normalized
        or not right.normalized
    ):
        return 0.0

    return SequenceMatcher(
        None,
        left.normalized,
        right.normalized,
    ).ratio()

def same_route_shape(
    response: ResponseFingerprint,
    baseline: ResponseFingerprint,
    *,
    threshold: float = 0.92,
) -> bool:
    if (
        response.status_code
        != baseline.status_code
    ):
        return False

    score = similarity(
        response,
        baseline,
    )

    if score >= threshold:
        return True

    if (
        response.title
        and baseline.title
        and response.title.casefold()
        == baseline.title.casefold()
        and score >= 0.82
    ):
        return True

    return False

def build_soft404_baselines(
    ctx: WebScanContext,
    *,
    count: int = 2,
) -> list[ResponseFingerprint]:
    baselines = []
    session = create_session()

    try:
        for _ in range(
            max(
                1,
                min(
                    3,
                    count,
                ),
            )
        ):
            random_path = (
                f"/__vulnscope_missing_"
                f"{secrets.token_hex(10)}"
            )

            try:
                response = cached_request(
                    session,
                    "GET",
                    urljoin(
                        ctx.origin + "/",
                        random_path.lstrip("/"),
                    ),
                    timeout=(2.5, 4.5),
                    allow_redirects=True,
                )
            except Exception:
                continue

            baselines.append(
                fingerprint_response(
                    response
                )
            )

    finally:
        session.close()

    return baselines

def looks_like_soft404(
    response: Any,
    baselines: list[ResponseFingerprint],
    *,
    threshold: float = 0.92,
) -> tuple[bool, float]:
    if not baselines:
        return False, 0.0

    current = fingerprint_response(
        response
    )

    scores = [
        similarity(
            current,
            baseline,
        )
        for baseline in baselines
        if (
            current.status_code
            == baseline.status_code
        )
    ]

    if not scores:
        return False, 0.0

    best = max(scores)

    shaped = any(
        same_route_shape(
            current,
            baseline,
            threshold=threshold,
        )
        for baseline in baselines
    )

    return shaped, best

def content_type_matches(
    response: Any,
    expected: list[str] | tuple[str, ...],
) -> bool:
    if not expected:
        return True

    actual = str(
        response.headers.get(
            "Content-Type",
            "",
        )
    ).split(
        ";",
        1,
    )[0].strip().lower()

    return any(
        actual == item.lower()
        or actual.startswith(
            item.lower()
        )
        for item in expected
    )

def same_origin(
    first: str,
    second: str,
) -> bool:
    a = urlsplit(
        str(first or "")
    )
    b = urlsplit(
        str(second or "")
    )

    return (
        a.scheme.lower(),
        a.hostname,
        a.port,
    ) == (
        b.scheme.lower(),
        b.hostname,
        b.port,
    )
