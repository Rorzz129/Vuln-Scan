from __future__ import annotations

from pathlib import Path
from time import perf_counter
from typing import Any, Callable

from target.manager import build_target
from scanners.dns_scanner import scan_dns
from scanners.http_scanner import scan_http
from scanners.nmap_scanner import scan_target
from web_checks.engine import scan_web
from web_checks.technologies import detect_web_technologies
from fingerprint.engine import fingerprint_nmap
from fingerprint.http_fingerprint import fingerprint_http
from cve.engine import scan_technology_cves_detailed
from analysis.risk import build_risk_summary
from analysis.report import build_scan_report, save_json_report, save_html_report, save_markdown_report, save_pentest_v2_report
from analysis.dedup import merge_findings
from analysis.profiles import get_profile
from analysis.health import build_scan_health
from analysis.quality_v8 import enrich_technologies_v8, correlate, prioritize_findings
from analysis.false_positive_v8 import reduce_false_positives
from analysis.scope import build_scope
from analysis.endpoint_intel import build_endpoint_map
from analysis.js_analysis import analyze_javascript
from analysis.api_analyzer import analyze_api
from analysis.tls_analyzer import analyze_tls
from analysis.verification import verify_findings
from analysis.resume import save_stage, clear_state
from cve.intelligence_v2 import enrich_for_cpe
from analysis.assets import discover_assets
from web_checks.crawler import crawl
from gui.workspace import update_workspace_from_scan
from technology_intel.engine import enrich_technologies
from template_engine.engine import run_templates

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
REPORTS_DIR = BASE_DIR / "reports"

ProgressCallback = Callable[[int, str], None]
LogCallback = Callable[[str], None]


def merge_technologies(technologies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    confidence_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

    for technology in technologies or []:
        if not isinstance(technology, dict):
            continue

        name = str(
            technology.get("name")
            or technology.get("product")
            or ""
        ).strip()

        if not name:
            continue

        key = name.casefold()
        candidate = dict(technology)
        evidence = candidate.get("evidence") or []

        if isinstance(evidence, str):
            evidence = [evidence]

        candidate["evidence"] = [
            str(item)
            for item in evidence
            if str(item).strip()
        ]

        current = merged.get(key)

        if current is None:
            merged[key] = candidate
            continue

        current_version = str(current.get("version") or "").strip()
        new_version = str(candidate.get("version") or "").strip()

        if new_version and not current_version:
            current["version"] = new_version
        elif new_version and current_version and new_version != current_version:
            alternate_versions = current.setdefault("alternate_versions", [])
            if new_version not in alternate_versions:
                alternate_versions.append(new_version)

        current_confidence = str(current.get("confidence") or "LOW").upper()
        new_confidence = str(candidate.get("confidence") or "LOW").upper()

        if confidence_order.get(new_confidence, 0) > confidence_order.get(current_confidence, 0):
            current["confidence"] = new_confidence

        if current.get("port") is None and candidate.get("port") is not None:
            current["port"] = candidate.get("port")

        current_evidence = current.setdefault("evidence", [])
        if isinstance(current_evidence, str):
            current_evidence = [current_evidence]
            current["evidence"] = current_evidence

        for item in candidate.get("evidence", []):
            if item not in current_evidence:
                current_evidence.append(item)

        sources = [
            source.strip()
            for source in str(current.get("source") or "").split(",")
            if source.strip()
        ]

        candidate_sources = [
            source.strip()
            for source in str(candidate.get("source") or "").split(",")
            if source.strip()
        ]

        for source in candidate_sources:
            if source not in sources:
                sources.append(source)

        if sources:
            current["source"] = ",".join(sources)

        for field in ("service", "extra"):
            if not current.get(field) and candidate.get(field):
                current[field] = candidate.get(field)

    return sorted(
        merged.values(),
        key=lambda item: (
            str(item.get("name") or "").casefold(),
            str(item.get("version") or ""),
        ),
    )


class ScanCancelled(Exception):
    pass


class Scanner:
    def __init__(
        self,
        target: str,
        profile: str = "NORMAL",
        *,
        reports_dir: str | Path | None = None,
        templates_dir: str | Path | None = None,
        save_json: bool = True,
        save_html: bool = True,
        max_cves_per_technology: int = 500,
        allow_subdomains: bool = True,
        scope_exclusions: list[str] | None = None,
        resume_enabled: bool = True,
        progress: ProgressCallback | None = None,
        log: LogCallback | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self.target_input = target.strip()
        self.profile = get_profile(profile).name
        self.reports_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
        self.templates_dir = Path(templates_dir) if templates_dir else TEMPLATES_DIR
        self.save_json = save_json
        self.save_html = save_html
        self.max_cves_per_technology = max(1, int(max_cves_per_technology))
        self.allow_subdomains = bool(allow_subdomains)
        self.scope_exclusions = list(scope_exclusions or [])
        self.resume_enabled = bool(resume_enabled)
        self.progress = progress or (lambda _value, _message: None)
        self.log = log or (lambda _message: None)
        self.cancelled = cancelled or (lambda: False)

    def _stage(self, value: int, message: str) -> None:
        if self.cancelled():
            raise ScanCancelled()
        self.progress(value, message)
        self.log(message)

    def run(self) -> dict[str, Any]:
        started = perf_counter()

        if not self.target_input:
            raise ValueError("Target cannot be empty")

        self._stage(3, "Resolving target")
        target = build_target(self.target_input)

        if target is None:
            raise ValueError("Invalid or unresolved target")

        scope = build_scope(
            target.scan_target,
            allow_subdomains=self.allow_subdomains,
            exclusions=self.scope_exclusions,
        )

        # Every stage result is initialized up-front so later reporting/UI code
        # always receives a valid object, even when a stage is skipped or fails.
        assets_result: dict[str, Any] = {
            "assets": [],
            "subdomains": [],
            "count": 0,
        }
        crawl_result: dict[str, Any] = {
            "pages": [],
            "forms": [],
            "parameters": [],
            "visited": 0,
        }
        js_analysis: dict[str, Any] = {
            "scripts": [],
            "api_endpoints": [],
            "websocket_endpoints": [],
            "parameters": [],
            "source_maps": [],
            "technologies": [],
        }
        endpoint_intel: dict[str, Any] = {
            "endpoints": [],
            "categories": {},
            "count": 0,
        }
        api_analysis: dict[str, Any] = {
            "types": [],
            "methods": [],
            "documentation_endpoints": [],
            "public_candidates": [],
            "endpoint_count": 0,
            "parameter_count": 0,
        }
        tls_result: dict[str, Any] = {
            "enabled": False,
            "findings": [],
        }

        self._stage(10, "Enumerating DNS records")
        target.dns = scan_dns(target.scan_target) or {}
        if self.resume_enabled: save_stage(target.original, "dns", target.dns)

        self._stage(18, "Analyzing HTTP service")
        target.http = scan_http(target.scan_target)
        if self.resume_enabled: save_stage(target.original, "http", target.http)

        self._stage(28, "Discovering ports and services with Nmap")
        target.nmap = scan_target(target.scan_target) or {}
        if self.resume_enabled: save_stage(target.original, "nmap", target.nmap)

        self._stage(40, "Fingerprinting technologies")
        technologies = fingerprint_nmap(target.nmap) or []

        if target.http:
            technologies.extend(fingerprint_http(target.http) or [])
            web_url = target.http.get("url")

            if web_url:
                try:
                    technologies.extend(
                        detect_web_technologies(web_url, verbose=False) or []
                    )
                except Exception as exc:
                    self.log(f"Technology detection warning: {exc}")

        technologies = merge_technologies(technologies)

        try:
            technologies = enrich_technologies(
                technologies,
                target.http.get("url") if target.http else None,
            )
        except Exception as exc:
            self.log(f"Technology intelligence warning: {exc}")

        target.technologies = enrich_technologies_v8(enrich_for_cpe(technologies))

        self._stage(52, "Running web security and discovery analysis")
        web_report: dict[str, Any] = {}
        web_findings: list[dict[str, Any]] = []

        if target.http and target.http.get("url"):
            web_report = scan_web(
                target.http["url"],
                verbose=False,
                profile=self.profile,
            )
            web_findings = web_report.get("findings", [])

        self._stage(58, "Crawling application surface")

        if target.http and target.http.get("url"):
            try:
                crawl_result = crawl(
                    target.http["url"],
                    max_pages=(
                        12 if self.profile == "FAST"
                        else 30 if self.profile == "NORMAL"
                        else 60
                    ),
                    max_depth=(
                        1 if self.profile == "FAST"
                        else 2 if self.profile == "NORMAL"
                        else 3
                    ),
                )
            except Exception as exc:
                self.log(f"Crawler warning: {exc}")

        self._stage(62, "Building asset inventory")

        try:
            assets_result = discover_assets(
                target.original,
                dns_data=target.dns,
                deep=(self.profile == "DEEP"),
            )
        except Exception as exc:
            self.log(f"Asset discovery warning: {exc}")

        self._stage(66, "Analyzing JavaScript, endpoints, API and TLS")

        if target.http and target.http.get("url"):
            base_url = target.http["url"]

            try:
                from web_checks.common import (
                    create_session,
                    cached_request,
                    response_text,
                )

                session = create_session()
                try:
                    response = cached_request(
                        session,
                        "GET",
                        base_url,
                        timeout=(2.5, 5.0),
                    )
                    html = response_text(
                        response,
                        limit=1_200_000,
                    )
                finally:
                    session.close()

                js_analysis = analyze_javascript(
                    base_url,
                    html,
                    max_scripts=(
                        6 if self.profile == "FAST"
                        else 10 if self.profile == "NORMAL"
                        else 15
                    ),
                )

                if js_analysis.get("technologies"):
                    target.technologies = enrich_technologies_v8(enrich_for_cpe(
                        merge_technologies(
                            [
                                *target.technologies,
                                *js_analysis["technologies"],
                            ]
                        )
                    ))

            except Exception as exc:
                self.log(
                    f"JavaScript analysis warning: {exc}"
                )

            try:
                endpoint_intel = build_endpoint_map(
                    crawl_result,
                    js_analysis,
                )
                api_analysis = analyze_api(
                    endpoint_intel,
                    crawl_result,
                    js_analysis,
                )
            except Exception as exc:
                self.log(
                    f"Endpoint/API analysis warning: {exc}"
                )

            try:
                tls_result = analyze_tls(base_url)
            except Exception as exc:
                tls_result = {
                    "enabled": False,
                    "findings": [],
                    "error": str(exc),
                }
                self.log(
                    f"TLS analysis warning: {exc}"
                )

        self._stage(68, "Running template security analysis")
        template_result: dict[str, Any] = {}
        template_findings: list[dict[str, Any]] = []

        if target.http and target.http.get("url"):
            template_result = run_templates(
                target.http["url"],
                self.templates_dir,
                verbose=False,
                technologies=target.technologies,
                profile=self.profile,
                base_status=(
                    web_report.get("status_code")
                    if web_report
                    else target.http.get("status_code")
                ),
            )
            template_findings = template_result.get("findings", [])

        self._stage(78, "Consolidating findings")
        merged_result = merge_findings(web_findings, template_findings)
        consolidated_findings = prioritize_findings(reduce_false_positives(verify_findings(merged_result.get("findings", []))))
        duplicates_merged = int(merged_result.get("duplicates_removed", 0))

        self._stage(86, "Correlating CPE and CVE data")
        cve_result = scan_technology_cves_detailed(
            target.technologies,
            max_cves_per_technology=self.max_cves_per_technology,
            verbose=False,
        )

        target.vulnerabilities = cve_result.get("vulnerabilities", [])
        cpe_diagnostics = cve_result.get("diagnostics", [])

        correlation = correlate(
            endpoints=endpoint_intel.get("endpoints", []),
            technologies=target.technologies,
            vulnerabilities=target.vulnerabilities,
            findings=consolidated_findings,
        )

        unresolved_cpes = [
            item
            for item in cpe_diagnostics
            if item.get("status") == "UNRESOLVED"
        ]

        scan_health = build_scan_health(
            http_status=(
                web_report.get("status_code")
                if web_report
                else (
                    target.http.get("status_code")
                    if target.http
                    else None
                )
            ),
            web_report=web_report,
            template_report=template_result,
            cpe_diagnostics=cpe_diagnostics,
            profile=self.profile,
        )

        for index, tls_finding in enumerate(
            tls_result.get("findings", []),
            start=1,
        ):
            consolidated_findings.append(
                {
                    "id": f"TLS-V7-{index:03d}",
                    "title": tls_finding.get("title"),
                    "severity": tls_finding.get("severity", "INFO"),
                    "confidence": "HIGH",
                    "verification_state": "LIKELY",
                    "verification_reason": (
                        "TLS handshake/certificate data was directly observed."
                    ),
                    "category": "TLS",
                    "url": target.http.get("url") if target.http else "",
                    "evidence": tls_finding.get("evidence", ""),
                    "recommendation": (
                        "Review TLS configuration and certificate lifecycle."
                    ),
                }
            )

        risk = build_risk_summary(
            consolidated_findings,
            target.vulnerabilities,
            unresolved_cpes,
        )

        self._stage(94, "Building scan report")
        report = build_scan_report(
            target,
            web_findings,
            target.vulnerabilities,
            cpe_diagnostics,
            template_findings,
            consolidated_findings,
            self.profile,
            scan_health,
        )

        paths: dict[str, str] = {}

        if self.save_json:
            paths["json"] = save_json_report(
                report,
                output_dir=str(self.reports_dir),
            )

        if self.save_html:
            paths["html"] = save_html_report(
                report,
                output_dir=str(self.reports_dir),
            )

        paths["markdown"] = save_markdown_report(
            report,
            output_dir=str(self.reports_dir),
        )

        versioned = sum(
            1
            for technology in target.technologies
            if technology.get("version")
        )

        tech_count = len(target.technologies)
        version_coverage = round(
            versioned / tech_count * 100,
            1,
        ) if tech_count else 100.0

        result = {
            "target": {
                "original": target.original,
                "ip": target.ip,
                "hostname": target.hostname,
                "scan_target": target.scan_target,
            },
            "dns": target.dns,
            "http": target.http,
            "nmap": target.nmap,
            "technologies": target.technologies,
            "web_findings": web_findings,
            "web_checks": web_report.get("checks", []) if web_report else [],
            "web_cache": web_report.get("cache", {}) if web_report else {},
            "template_findings": template_findings,
            "findings": consolidated_findings,
            "duplicates_merged": duplicates_merged,
            "vulnerabilities": target.vulnerabilities,
            "cpe_diagnostics": cpe_diagnostics,
            "correlation": correlation,
            "scan_health": scan_health,
            "risk": risk,
            "profile": self.profile,
            "version_coverage": version_coverage,
            "reports": paths,
            "assets": assets_result,
            "crawl": crawl_result,
            "scope": scope.to_dict(),
            "endpoint_intel": endpoint_intel,
            "js_analysis": js_analysis,
            "api_analysis": api_analysis,
            "tls": tls_result,
            "duration": round(perf_counter() - started, 2),
            "raw_report": report,
        }

        try:
            result["workspace"] = update_workspace_from_scan(result)
        except Exception as exc:
            self.log(f"Workspace warning: {exc}")

        try:
            paths["pentest_v2"] = save_pentest_v2_report(result, output_dir=str(self.reports_dir))
        except Exception as exc:
            self.log(f"Pentest V2 report warning: {exc}")
        if self.resume_enabled: clear_state(target.original)
        self._stage(100, "Scan completed")
        return result
