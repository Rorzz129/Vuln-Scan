from __future__ import annotations

from typing import Any

from cve.client import search_applicable_cves
from cve.cpe import (
    build_concrete_cpe,
    normalize_version,
    resolve_cpes,
    resolve_product_cpes,
    diagnose_cpe,
)
from cve.parser import SEVERITY_ORDER


def scan_technology_cves(
    technologies: list[dict[str, Any]],
    *,
    max_cpes_per_technology: int = 3,
    max_cves_per_technology: int = 500,
    verbose: bool = True,
) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for technology in technologies:
        if not isinstance(technology, dict):
            continue

        product = str(technology.get("name") or "").strip()
        version = normalize_version(technology.get("version"))
        port = technology.get("port")

        product_confidence = int(
            technology.get(
                "confidence_score",
                100,
            )
            or 0
        )

        version_confidence = str(
            technology.get(
                "version_confidence",
                "HIGH"
                if version
                else "UNKNOWN",
            )
        ).upper()

        if (
            product_confidence < 55
            or version_confidence == "LOW"
            or technology.get(
                "version_conflict"
            )
        ):
            if verbose:
                print(
                    f"[!] Skipping {product or 'Unknown'}: "
                    "technology/version confidence gate not satisfied"
                )
            continue

        if not product or version is None:
            if verbose and product:
                print(f"[!] Skipping {product}: version unknown")
            continue

        if verbose:
            print(f"[+] Resolving CPE: {product} {version}")

        exact = resolve_cpes(
            product,
            version,
            max_results=max_cpes_per_technology,
        )

        candidates: list[dict[str, Any]] = []

        for item in exact:
            candidates.append({
                "source_cpe": item["cpe"],
                "score": int(item["score"]),
                "match_mode": "exact-cpe",
            })

        if not candidates:
            if verbose:
                print(
                    f"[>] No exact CPE for {product} {version}; "
                    "using product identity with NVD applicability matching"
                )

            product_candidates = resolve_product_cpes(
                product,
                max_results=max_cpes_per_technology,
            )

            for item in product_candidates:
                candidates.append({
                    "source_cpe": item["cpe"],
                    "score": int(item["score"]),
                    "match_mode": "nvd-applicability",
                })

        if not candidates:
            if verbose:
                print(f"[!] No reliable CPE identity found for {product} {version}")
            continue

        for candidate in candidates:
            source_cpe = candidate["source_cpe"]
            concrete_cpe = build_concrete_cpe(
                source_cpe,
                version,
            )

            if not concrete_cpe:
                if verbose:
                    print(f"[!] Could not build target CPE from {source_cpe}")
                continue

            if verbose:
                print(
                    f"[+] Target CPE: {concrete_cpe} "
                    f"(mode={candidate['match_mode']}, score={candidate['score']})"
                )

            try:
                cves = search_applicable_cves(
                    concrete_cpe,
                    limit=max_cves_per_technology,
                )
            except Exception as error:
                if verbose:
                    print(
                        f"[!] NVD applicability lookup failed for "
                        f"{concrete_cpe}: {error}"
                    )
                continue

            if verbose:
                print(
                    f"[+] {len(cves)} NVD-applicable CVE(s) "
                    f"for {product} {version}"
                )

            for cve in cves:
                cve_id = str(cve.get("id") or "").strip()

                if not cve_id:
                    continue

                key = (
                    product.casefold(),
                    version.casefold(),
                    str(port),
                    cve_id,
                )

                if key in seen:
                    continue

                seen.add(key)

                vulnerabilities.append({
                    "technology": product,
                    "version": version,
                    "port": port,
                    "cpe": concrete_cpe,
                    "cpe_score": candidate["score"],
                    "match_mode": candidate["match_mode"],
                    "status": "APPLICABLE",
                    "cve": cve,
                })

    vulnerabilities.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(
                str(
                    item["cve"].get("severity")
                    or "UNKNOWN"
                ).upper(),
                0,
            ),
            -float(item["cve"].get("cvss") or 0),
            str(item["cve"].get("id") or ""),
        ),
    )

    return vulnerabilities


def scan_technology_cves_detailed(
    technologies: list[dict[str, Any]],
    *,
    max_cpes_per_technology: int = 3,
    max_cves_per_technology: int = 500,
    verbose: bool = True,
) -> dict[str, Any]:
    diagnostics: list[dict[str, Any]] = []

    for technology in technologies:
        if not isinstance(technology, dict):
            continue

        product = str(technology.get("name") or "").strip()
        version = technology.get("version")
        port = technology.get("port")

        product_confidence = int(
            technology.get(
                "confidence_score",
                100,
            )
            or 0
        )

        version_confidence = str(
            technology.get(
                "version_confidence",
                "HIGH"
                if version
                else "UNKNOWN",
            )
        ).upper()

        if (
            product_confidence < 55
            or version_confidence == "LOW"
            or technology.get(
                "version_conflict"
            )
        ):
            diagnostic = {
                "product": product,
                "version": normalize_version(
                    version
                ),
                "status": "NOT_APPLICABLE",
                "confidence": "LOW",
                "reason": (
                    "technology/version confidence gate not satisfied"
                ),
                "candidates": [],
            }
        else:
            diagnostic = diagnose_cpe(
                product,
                version,
            )

        diagnostic["port"] = port
        diagnostic[
            "technology_confidence_score"
        ] = product_confidence
        diagnostic[
            "version_confidence"
        ] = version_confidence

        diagnostics.append(
            diagnostic
        )

    vulnerabilities = scan_technology_cves(
        technologies,
        max_cpes_per_technology=max_cpes_per_technology,
        max_cves_per_technology=max_cves_per_technology,
        verbose=verbose,
    )

    return {
        "vulnerabilities": vulnerabilities,
        "diagnostics": diagnostics,
    }
