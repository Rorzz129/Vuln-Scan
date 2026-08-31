from __future__ import annotations

from collections import Counter
from typing import Any
import re

TECH_VERSION_PATTERNS = {
    "Apache httpd": (
        re.compile(r"(?:Apache(?: HTTP Server)?|httpd)[/\s-]+([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
    ),
    "nginx": (
        re.compile(r"\bnginx/([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
    ),
    "OpenResty": (
        re.compile(r"\bopenresty/([0-9]+\.[0-9]+(?:\.[0-9]+){0,3})", re.I),
    ),
    "PHP": (
        re.compile(r"\bPHP/?([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
    ),
    "PrestaShop": (
        re.compile(r"\bPrestaShop(?:\s+|[/@-])([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
        re.compile(r"prestashop(?:\.min)?[-.@]([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
    ),
    "WordPress": (
        re.compile(r"\bWordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
        re.compile(r"(?:wp-includes|wp-content)/[^\"']+[?&]ver=([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
    ),
    "WooCommerce": (
        re.compile(r"woocommerce[^\"']+[?&]ver=([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
    ),
    "Angular": (
        re.compile(r'ng-version=["\']([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})["\']', re.I),
    ),
    "jQuery": (
        re.compile(r"jquery[-.@]([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
        re.compile(r"jQuery\s+v([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
    ),
    "Bootstrap": (
        re.compile(r"bootstrap(?:\.bundle)?[-.@]([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
        re.compile(r"Bootstrap\s+v([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})", re.I),
    ),
}

def clean_version(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip().lstrip("vV")

    if not text or text.casefold() in {
        "unknown",
        "none",
        "null",
        "n/a",
        "-",
        "*",
    }:
        return None

    match = re.match(
        r"^([0-9]+(?:\.[0-9A-Za-z_-]+){1,4})",
        text,
    )

    return match.group(1) if match else None

def versions_from_text(
    technology: str,
    text: Any,
) -> list[str]:
    source = str(text or "")
    values: list[str] = []

    for pattern in TECH_VERSION_PATTERNS.get(technology, ()):
        for match in pattern.finditer(source):
            version = clean_version(match.group(1))
            if version and version not in values:
                values.append(version)

    return values

def choose_version(
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    usable = [
        item
        for item in candidates
        if clean_version(item.get("version"))
    ]

    if not usable:
        return {
            "version": None,
            "confidence": "UNKNOWN",
            "score": 0,
            "conflict": False,
            "candidates": [],
        }

    weights: Counter[str] = Counter()
    evidence_count: Counter[str] = Counter()

    for item in usable:
        version = clean_version(item.get("version"))
        if not version:
            continue

        weight = float(item.get("weight") or 0.5)
        weights[version] += weight
        evidence_count[version] += 1

    ranked = sorted(
        weights,
        key=lambda version: (
            weights[version],
            evidence_count[version],
            version,
        ),
        reverse=True,
    )

    winner = ranked[0]
    total_weight = sum(weights.values()) or 1.0
    share = weights[winner] / total_weight
    conflict = len(ranked) > 1 and share < 0.8

    if conflict:
        confidence = "LOW"
        score = int(round(share * 100))
    elif evidence_count[winner] >= 2 or weights[winner] >= 0.9:
        confidence = "HIGH"
        score = min(100, int(round(65 + 25 * share)))
    else:
        confidence = "MEDIUM"
        score = min(89, int(round(50 + 30 * share)))

    return {
        "version": winner,
        "confidence": confidence,
        "score": score,
        "conflict": conflict,
        "candidates": [
            {
                "version": version,
                "weight": round(weights[version], 3),
                "evidence_count": evidence_count[version],
            }
            for version in ranked
        ],
    }
