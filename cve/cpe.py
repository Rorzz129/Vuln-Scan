from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from cve.nvd_client import NVD_CPE_API_URL, nvd_paginated_get

UNKNOWN_VERSIONS = {"", "unknown", "none", "null", "-", "*", "n/a"}

CPE_PRODUCT_ALIASES = {
    "apache http server": "apache httpd",
    "apache httpd": "apache httpd",
    "microsoft iis": "iis",
    "prestashop": "prestashop",
    "wordpress": "wordpress",
    "woocommerce": "woocommerce",
    "drupal": "drupal",
    "apache tomcat": "apache tomcat",
}


PRODUCT_PROFILES = {
    "apache httpd": {
        "queries": ("Apache HTTP Server",),
        "vendor": ("apache",),
        "product": ("http_server",),
    },
    "apache http server": {
        "queries": ("Apache HTTP Server",),
        "vendor": ("apache",),
        "product": ("http_server",),
    },
    "apache": {
        "queries": ("Apache HTTP Server",),
        "vendor": ("apache",),
        "product": ("http_server",),
    },
    "openssh": {
        "queries": ("OpenSSH",),
        "vendor": ("openbsd",),
        "product": ("openssh",),
    },
    "nginx": {
        "queries": ("nginx",),
        "vendor": ("f5", "nginx"),
        "product": ("nginx",),
    },
    "prestashop": {
        "queries": ("PrestaShop",),
        "vendor": ("prestashop",),
        "product": ("prestashop",),
    },
    "wordpress": {
        "queries": ("WordPress",),
        "vendor": ("wordpress",),
        "product": ("wordpress",),
    },
    "woocommerce": {
        "queries": ("WooCommerce",),
        "vendor": ("woocommerce", "automattic"),
        "product": ("woocommerce",),
    },
    "drupal": {
        "queries": ("Drupal",),
        "vendor": ("drupal",),
        "product": ("drupal",),
    },
    "apache tomcat": {
        "queries": ("Apache Tomcat",),
        "vendor": ("apache",),
        "product": ("tomcat",),
    },
    "php": {
        "queries": ("PHP",),
        "vendor": ("php",),
        "product": ("php",),
    },
    "postgresql": {
        "queries": ("PostgreSQL",),
        "vendor": ("postgresql",),
        "product": ("postgresql",),
    },
    "mysql": {
        "queries": ("MySQL Server",),
        "vendor": ("oracle", "mysql"),
        "product": ("mysql", "mysql_server"),
    },
    "microsoft iis": {
        "queries": ("Microsoft Internet Information Services",),
        "vendor": ("microsoft",),
        "product": ("internet_information_services",),
    },
    "iis": {
        "queries": ("Microsoft Internet Information Services",),
        "vendor": ("microsoft",),
        "product": ("internet_information_services",),
    },
}


@dataclass(slots=True)
class ParsedCPE:
    raw: str
    part: str
    vendor: str
    product: str
    version: str
    update: str


def normalize_name(value: Any) -> str:
    text = unquote(str(value or "")).casefold()
    text = text.replace("\\", "")
    text = re.sub(r"[_:/+.-]+", " ", text)
    return " ".join(text.split())


def normalize_version(version: Any) -> str | None:
    value = str(version or "").strip()

    if value.casefold() in UNKNOWN_VERSIONS:
        return None

    value = value.removeprefix("v").removeprefix("V")
    value = value.split()[0].strip()

    return value or None


def parse_cpe_name(cpe_name: str) -> ParsedCPE | None:
    parts = str(cpe_name or "").split(":")

    if (
        len(parts) < 7
        or parts[0] != "cpe"
        or parts[1] != "2.3"
    ):
        return None

    return ParsedCPE(
        raw=cpe_name,
        part=parts[2],
        vendor=parts[3],
        product=parts[4],
        version=parts[5],
        update=parts[6],
    )


def build_concrete_cpe(
    product_cpe: str,
    version: str,
) -> str | None:
    parts = str(product_cpe or "").split(":")
    normalized_version = normalize_version(version)

    if (
        normalized_version is None
        or len(parts) < 13
        or parts[0] != "cpe"
        or parts[1] != "2.3"
    ):
        return None

    if parts[2] in {"", "*", "-"}:
        return None

    if parts[3] in {"", "*", "-"}:
        return None

    if parts[4] in {"", "*", "-"}:
        return None

    parts[5] = normalized_version

    for index in range(6, 13):
        if not parts[index]:
            parts[index] = "*"

    return ":".join(parts[:13])


def to_product_pattern(cpe_name: str) -> str | None:
    parts = str(cpe_name or "").split(":")

    if (
        len(parts) < 13
        or parts[0] != "cpe"
        or parts[1] != "2.3"
    ):
        return None

    parts[5] = "*"
    parts[6] = "*"

    for index in range(7, 13):
        if not parts[index]:
            parts[index] = "*"

    return ":".join(parts[:13])


def _profile(product: str) -> dict[str, tuple[str, ...]] | None:
    normalized = normalize_name(product)
    normalized = CPE_PRODUCT_ALIASES.get(
        normalized,
        normalized,
    )

    for key, profile in PRODUCT_PROFILES.items():
        if normalized == normalize_name(key):
            return profile

    return None


def get_search_queries(product: str) -> list[str]:
    profile = _profile(product)

    if profile:
        return list(profile["queries"])

    return [str(product).strip()]


def extract_cpe_name(product_data: dict[str, Any]) -> str | None:
    cpe_data = product_data.get("cpe", {})

    if not isinstance(cpe_data, dict):
        return None

    cpe_name = cpe_data.get("cpeName")

    return cpe_name if isinstance(cpe_name, str) else None


def _title_values(product_data: dict[str, Any]) -> list[str]:
    cpe_data = product_data.get("cpe", {})

    if not isinstance(cpe_data, dict):
        return []

    titles = cpe_data.get("titles", [])
    results: list[str] = []

    if not isinstance(titles, list):
        return results

    for title in titles:
        if not isinstance(title, dict):
            continue

        value = str(title.get("title") or "").strip()

        if value:
            results.append(value)

    return results


def _version_matches(
    parsed: ParsedCPE,
    requested_version: str | None,
) -> bool:
    requested = normalize_version(requested_version)

    if requested is None:
        return True

    if normalize_version(parsed.version) == requested:
        return True

    if parsed.update not in {"", "*", "-"}:
        combined = f"{parsed.version}{parsed.update}"

        if normalize_version(combined) == requested:
            return True

    return False


def _score_candidate(
    product: str,
    product_data: dict[str, Any],
    requested_version: str | None,
    *,
    require_version: bool,
) -> int:
    cpe_name = extract_cpe_name(product_data)
    parsed = parse_cpe_name(cpe_name or "")

    if parsed is None or parsed.part not in {"a", "o", "h"}:
        return -1000

    if require_version and not _version_matches(parsed, requested_version):
        return -1000

    profile = _profile(product)
    requested_name = normalize_name(product)
    vendor = normalize_name(parsed.vendor)
    cpe_product = normalize_name(parsed.product)
    titles = [normalize_name(value) for value in _title_values(product_data)]

    score = 0

    if profile:
        allowed_vendors = {
            normalize_name(value)
            for value in profile["vendor"]
        }
        allowed_products = {
            normalize_name(value)
            for value in profile["product"]
        }

        if vendor not in allowed_vendors:
            return -1000

        if cpe_product not in allowed_products:
            return -1000

        score += 100

    requested_tokens = {
        token
        for token in requested_name.split()
        if len(token) >= 2
    }

    title_tokens: set[str] = set()

    for title in titles:
        title_tokens.update(title.split())

    overlap = len(
        requested_tokens
        & (set(cpe_product.split()) | title_tokens)
    )

    score += overlap * 10

    if requested_name == cpe_product:
        score += 35

    if any(requested_name in title for title in titles):
        score += 20

    if requested_version and _version_matches(parsed, requested_version):
        score += 20

    return score


def request_cpes(
    query: str,
    *,
    limit: int = 500,
) -> list[dict[str, Any]]:
    return nvd_paginated_get(
        NVD_CPE_API_URL,
        {"keywordSearch": query},
        result_key="products",
        limit=max(1, limit),
        results_per_page=min(max(1, limit), 200),
    )


def resolve_cpes(
    product: str,
    version: str | None = None,
    *,
    max_results: int = 5,
    candidate_limit: int = 500,
) -> list[dict[str, Any]]:
    if not str(product or "").strip():
        return []

    candidates: dict[str, dict[str, Any]] = {}

    for query in get_search_queries(product):
        for product_data in request_cpes(
            query,
            limit=candidate_limit,
        ):
            cpe_name = extract_cpe_name(product_data)

            if not cpe_name:
                continue

            score = _score_candidate(
                product,
                product_data,
                version,
                require_version=True,
            )

            if score < 0:
                continue

            result = {
                "cpe": cpe_name,
                "score": score,
                "titles": _title_values(product_data),
            }

            current = candidates.get(cpe_name)

            if current is None or score > current["score"]:
                candidates[cpe_name] = result

    return sorted(
        candidates.values(),
        key=lambda item: (
            -int(item["score"]),
            item["cpe"],
        ),
    )[:max_results]


def resolve_product_cpes(
    product: str,
    *,
    max_results: int = 3,
    candidate_limit: int = 500,
) -> list[dict[str, Any]]:
    if not str(product or "").strip():
        return []

    patterns: dict[str, dict[str, Any]] = {}

    for query in get_search_queries(product):
        for product_data in request_cpes(
            query,
            limit=candidate_limit,
        ):
            cpe_name = extract_cpe_name(product_data)

            if not cpe_name:
                continue

            score = _score_candidate(
                product,
                product_data,
                None,
                require_version=False,
            )

            if score < 0:
                continue

            pattern = to_product_pattern(cpe_name)

            if not pattern:
                continue

            result = {
                "cpe": pattern,
                "score": score,
                "titles": _title_values(product_data),
            }

            current = patterns.get(pattern)

            if current is None or score > current["score"]:
                patterns[pattern] = result

    return sorted(
        patterns.values(),
        key=lambda item: (
            -int(item["score"]),
            item["cpe"],
        ),
    )[:max_results]


def search_cpe(
    product: str,
    version: str | None = None,
    *,
    max_results: int = 5,
) -> list[str]:
    return [
        item["cpe"]
        for item in resolve_cpes(
            product,
            version,
            max_results=max_results,
        )
    ]


def diagnose_cpe(
    product: str,
    version: str | None,
) -> dict[str, Any]:
    normalized_version = normalize_version(version)

    if not str(product or "").strip():
        return {
            "product": product,
            "version": normalized_version,
            "status": "UNRESOLVED",
            "confidence": "LOW",
            "reason": "empty product name",
            "candidates": [],
        }

    if normalized_version is None:
        return {
            "product": product,
            "version": None,
            "status": "SKIPPED",
            "confidence": "LOW",
            "reason": "version unknown",
            "candidates": [],
        }

    exact = resolve_cpes(
        product,
        normalized_version,
        max_results=3,
    )

    if exact:
        return {
            "product": product,
            "version": normalized_version,
            "status": "RESOLVED",
            "mode": "exact-cpe",
            "confidence": "HIGH",
            "reason": "exact product/version CPE match",
            "candidates": exact,
        }

    product_level = resolve_product_cpes(
        product,
        max_results=3,
    )

    if product_level:
        return {
            "product": product,
            "version": normalized_version,
            "status": "RESOLVED",
            "mode": "nvd-applicability",
            "confidence": "MEDIUM",
            "reason": "product identity resolved; version delegated to NVD applicability",
            "candidates": product_level,
        }

    return {
        "product": product,
        "version": normalized_version,
        "status": "UNRESOLVED",
        "confidence": "LOW",
        "reason": "no reliable vendor/product CPE identity found",
        "candidates": [],
    }
