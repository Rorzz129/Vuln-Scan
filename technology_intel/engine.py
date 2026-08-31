from __future__ import annotations

from html import unescape
from math import prod
from typing import Any
from urllib.parse import urljoin
import re

from technology_intel.aliases import (
    canonical_name,
    known_aliases,
)
from technology_intel.versioning import (
    clean_version,
    versions_from_text,
    choose_version,
)
from web_checks.accuracy import same_origin
from web_checks.common import (
    create_session,
    cached_request,
    normalize_url,
    response_text,
)

SOURCE_WEIGHT = {
    "nmap": 0.95,
    "header": 0.90,
    "meta": 0.95,
    "cookie": 0.62,
    "html": 0.68,
    "javascript": 0.76,
    "asset": 0.72,
    "web": 0.60,
    "unknown": 0.45,
}

META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
    re.I,
)

ASSET_RE = re.compile(
    r'(?:src|href)=["\']([^"\']+\.(?:js|css)(?:\?[^"\']*)?)["\']',
    re.I,
)

def _source_weight(source: str) -> float:
    parts = [
        item.strip().casefold()
        for item in str(source or "unknown").split(",")
        if item.strip()
    ]

    if not parts:
        return SOURCE_WEIGHT["unknown"]

    return max(
        SOURCE_WEIGHT.get(
            part,
            SOURCE_WEIGHT["unknown"],
        )
        for part in parts
    )

def _confidence_score(
    evidence: list[dict[str, Any]],
) -> int:
    weights = [
        max(
            0.05,
            min(
                0.99,
                float(
                    item.get("weight")
                    or 0.4
                ),
            ),
        )
        for item in evidence
    ]

    if not weights:
        return 0

    score = 1.0 - prod(
        1.0 - weight
        for weight in weights
    )

    return int(
        round(
            min(
                0.99,
                score,
            )
            * 100
        )
    )

def _confidence_label(
    score: int,
) -> str:
    if score >= 85:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    return "LOW"

def _evidence_records(
    technology: dict[str, Any],
) -> list[dict[str, Any]]:
    source = str(
        technology.get("source")
        or "unknown"
    )
    base_weight = _source_weight(
        source
    )
    raw = technology.get(
        "evidence"
    ) or []

    if isinstance(raw, str):
        raw = [raw]

    records = []

    for item in raw:
        text = str(item).strip()

        if text:
            records.append(
                {
                    "source": source,
                    "text": text,
                    "weight": base_weight,
                }
            )

    if not records and source:
        records.append(
            {
                "source": source,
                "text": (
                    f"{technology.get('name') or technology.get('product') or 'Technology'} "
                    f"{technology.get('version') or ''}"
                ).strip(),
                "weight": base_weight,
            }
        )

    return records

def _version_candidates(
    canonical: str,
    technology: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    direct = clean_version(
        technology.get("version")
    )

    if direct:
        candidates.append(
            {
                "version": direct,
                "source": (
                    technology.get("source")
                    or "unknown"
                ),
                "weight": _source_weight(
                    str(
                        technology.get("source")
                        or "unknown"
                    )
                ),
                "evidence": "direct detector version",
            }
        )

    for alternate in (
        technology.get(
            "alternate_versions"
        )
        or []
    ):
        version = clean_version(
            alternate
        )

        if version:
            candidates.append(
                {
                    "version": version,
                    "source": "alternate",
                    "weight": 0.55,
                    "evidence": "alternate detected version",
                }
            )

    for record in evidence:
        for version in versions_from_text(
            canonical,
            record.get("text"),
        ):
            candidates.append(
                {
                    "version": version,
                    "source": record.get("source"),
                    "weight": record.get("weight"),
                    "evidence": record.get("text"),
                }
            )

    return candidates

def _web_intelligence(
    url: str,
) -> dict[str, Any]:
    session = create_session()

    try:
        response = cached_request(
            session,
            "GET",
            normalize_url(url),
            timeout=(3.5, 6.0),
        )

        headers = {
            str(key).lower(): str(value)
            for key, value
            in response.headers.items()
        }

        body = unescape(
            response_text(
                response,
                limit=1_500_000,
            )
        )

        meta = META_GENERATOR.findall(
            body
        )

        assets = []

        for value in ASSET_RE.findall(
            body
        ):
            full = urljoin(
                response.url,
                value,
            )

            if full not in assets:
                assets.append(full)

            if len(assets) >= 25:
                break

        asset_bodies = []

        for asset_url in assets[:6]:
            if not same_origin(
                response.url,
                asset_url,
            ):
                continue

            if not asset_url.lower().split(
                "?",
                1,
            )[0].endswith(
                ".js"
            ):
                continue

            try:
                asset_response = cached_request(
                    session,
                    "GET",
                    asset_url,
                    timeout=(2.5, 4.0),
                    allow_redirects=True,
                )
            except Exception:
                continue

            content_type = str(
                asset_response.headers.get(
                    "Content-Type",
                    "",
                )
            ).lower()

            if (
                "javascript"
                not in content_type
                and "text/plain"
                not in content_type
            ):
                continue

            asset_text = response_text(
                asset_response,
                limit=300000,
            )

            if asset_text:
                asset_bodies.append(
                    {
                        "url": asset_response.url,
                        "text": asset_text,
                    }
                )

        return {
            "url": response.url,
            "headers": headers,
            "body": body,
            "meta_generators": meta,
            "assets": assets,
            "asset_bodies": asset_bodies,
        }

    finally:
        session.close()

def _web_version_hints(
    canonical: str,
    web: dict[str, Any],
) -> list[dict[str, Any]]:
    candidates = []
    texts: list[
        tuple[str, str, float]
    ] = []

    headers = (
        web.get("headers")
        or {}
    )

    for header in (
        "server",
        "x-powered-by",
        "x-generator",
        "x-prestashop-version",
    ):
        value = headers.get(
            header
        )

        if value:
            texts.append(
                (
                    f"header:{header}",
                    value,
                    0.90,
                )
            )

    for value in (
        web.get(
            "meta_generators"
        )
        or []
    ):
        texts.append(
            (
                "meta",
                value,
                0.95,
            )
        )

    body = (
        web.get("body")
        or ""
    )

    if canonical in {
        "PrestaShop",
        "WordPress",
        "WooCommerce",
        "Angular",
        "jQuery",
        "Bootstrap",
    }:
        texts.append(
            (
                "html",
                body[:1_000_000],
                0.68,
            )
        )

    for asset in (
        web.get("assets")
        or []
    ):
        texts.append(
            (
                "asset",
                asset,
                0.72,
            )
        )

    for source, text, weight in texts:
        for version in versions_from_text(
            canonical,
            text,
        ):
            candidates.append(
                {
                    "version": version,
                    "source": source,
                    "weight": weight,
                    "evidence": (
                        text[:200]
                        if len(text) <= 200
                        else text[:197] + "..."
                    ),
                }
            )

    return candidates

def enrich_technologies(
    technologies: list[dict[str, Any]],
    url: str | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[
        str,
        dict[str, Any],
    ] = {}

    for technology in (
        technologies
        or []
    ):
        if not isinstance(
            technology,
            dict,
        ):
            continue

        raw_name = str(
            technology.get("name")
            or technology.get("product")
            or ""
        ).strip()

        if not raw_name:
            continue

        canonical = canonical_name(
            raw_name
        )
        key = canonical.casefold()
        evidence = _evidence_records(
            technology
        )

        current = grouped.get(
            key
        )

        if current is None:
            current = {
                "name": canonical,
                "canonical_name": canonical,
                "aliases": set(),
                "port": technology.get("port"),
                "service": technology.get("service"),
                "extra": technology.get("extra"),
                "source_parts": set(),
                "evidence_records": [],
                "version_candidates": [],
            }
            grouped[key] = current

        if (
            raw_name.casefold()
            != canonical.casefold()
        ):
            current["aliases"].add(
                raw_name
            )

        current["aliases"].update(
            known_aliases(
                canonical
            )
        )

        for source in str(
            technology.get("source")
            or "unknown"
        ).split(","):
            source = source.strip()

            if source:
                current[
                    "source_parts"
                ].add(
                    source
                )

        if (
            current.get("port")
            is None
            and technology.get("port")
            is not None
        ):
            current["port"] = (
                technology.get("port")
            )

        if (
            not current.get("service")
            and technology.get("service")
        ):
            current["service"] = (
                technology.get("service")
            )

        if (
            not current.get("extra")
            and technology.get("extra")
        ):
            current["extra"] = (
                technology.get("extra")
            )

        for record in evidence:
            if (
                record
                not in current[
                    "evidence_records"
                ]
            ):
                current[
                    "evidence_records"
                ].append(
                    record
                )

        current[
            "version_candidates"
        ].extend(
            _version_candidates(
                canonical,
                technology,
                evidence,
            )
        )

    web = None

    if url:
        try:
            web = _web_intelligence(
                url
            )
        except Exception:
            web = None

    results = []

    for current in grouped.values():
        canonical = current[
            "canonical_name"
        ]

        if web:
            web_candidates = (
                _web_version_hints(
                    canonical,
                    web,
                )
            )

            current[
                "version_candidates"
            ].extend(
                web_candidates
            )

            for candidate in web_candidates:
                record = {
                    "source": candidate.get(
                        "source"
                    ),
                    "text": candidate.get(
                        "evidence"
                    ),
                    "weight": candidate.get(
                        "weight"
                    ),
                }

                if (
                    record
                    not in current[
                        "evidence_records"
                    ]
                ):
                    current[
                        "evidence_records"
                    ].append(
                        record
                    )

        version_result = choose_version(
            current[
                "version_candidates"
            ]
        )

        product_score = _confidence_score(
            current[
                "evidence_records"
            ]
        )

        evidence_text = []

        for record in current[
            "evidence_records"
        ]:
            text = str(
                record.get("text")
                or ""
            ).strip()

            if (
                text
                and text
                not in evidence_text
            ):
                evidence_text.append(
                    text
                )

        results.append(
            {
                "name": canonical,
                "canonical_name": canonical,
                "version": version_result[
                    "version"
                ],
                "port": current.get(
                    "port"
                ),
                "service": current.get(
                    "service"
                ),
                "extra": current.get(
                    "extra"
                ),
                "source": ",".join(
                    sorted(
                        current[
                            "source_parts"
                        ]
                    )
                )
                or "unknown",
                "confidence": _confidence_label(
                    product_score
                ),
                "confidence_score": product_score,
                "version_confidence": version_result[
                    "confidence"
                ],
                "version_score": version_result[
                    "score"
                ],
                "version_conflict": version_result[
                    "conflict"
                ],
                "version_candidates": version_result[
                    "candidates"
                ],
                "aliases": sorted(
                    alias
                    for alias
                    in current["aliases"]
                    if (
                        alias.casefold()
                        != canonical.casefold()
                    )
                ),
                "evidence": evidence_text,
                "evidence_count": len(
                    evidence_text
                ),
            }
        )

    results.sort(
        key=lambda item: (
            -int(
                item.get(
                    "confidence_score"
                )
                or 0
            ),
            str(
                item.get("name")
                or ""
            ).casefold(),
        )
    )

    return results
