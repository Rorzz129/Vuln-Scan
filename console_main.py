from target.manager import build_target

from scanners.dns_scanner import scan_dns
from scanners.http_scanner import scan_http
from scanners.nmap_scanner import scan_target

from web_checks.engine import scan_web, scan_web_security
from web_checks.technologies import detect_web_technologies

from fingerprint.engine import fingerprint_nmap
from fingerprint.http_fingerprint import fingerprint_http

from cve.engine import scan_technology_cves_detailed
from analysis.risk import build_risk_summary, classify_web_finding
from analysis.report import build_scan_report, save_json_report, save_html_report
from template_engine.engine import run_templates
from analysis.dedup import merge_findings
from analysis.profiles import get_profile
from analysis.health import build_scan_health
from technology_intel.engine import enrich_technologies

import os
WIDTH = 70

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    GRAY = "\033[90m"
def c(text, color):
    return f"{color}{text}{C.RESET}"
def line(char="─", color=C.GRAY):
    print(c(char * WIDTH, color))
def section(title, icon="▸"):
    print()
    line("─", C.BLUE)
    print(f"  {c(icon, C.CYAN)} {c(title, C.BOLD + C.CYAN)}")
    line("─", C.BLUE)
def status(label, value, value_color=C.RESET):
    print(f"  {c(f'{label:<20}', C.DIM)} {c(str(value), value_color)}")
def info(msg):
    print(f"  {c('[*]', C.BLUE)} {msg}")
def success(msg):
    print(f"  {c('[+]', C.GREEN)} {msg}")
def warn(msg):
    print(f"  {c('[!]', C.YELLOW)} {msg}")
def error(msg):
    print(f"  {c('[!]', C.RED)} {msg}")
def empty(msg):
    print(f"  {c('└─', C.GRAY)} {c(msg, C.DIM)}")
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    clear()

    print(
        C.RED,
        """
   █████████        █████████     ███████████      █████   █████ █████  █████ █████       ██████   █████
  ███░░░░░███      ███░░░░░███   ░░███░░░░░███    ░░███   ░░███ ░░███  ░░███ ░░███       ░░██████ ░░███
 ░███    ░███     ███     ░░░     ░███    ░███     ░███    ░███  ░███   ░███  ░███        ░███░███ ░███
 ░███████████    ░███             ░██████████      ░███    ░███  ░███   ░███  ░███        ░███░░███░███
 ░███░░░░░███    ░███             ░███░░░░░███     ░░███   ███   ░███   ░███  ░███        ░███ ░░██████
 ░███    ░███    ░░███     ███    ░███    ░███      ░░░█████░    ░███   ░███  ░███      █ ░███  ░░█████
 █████   █████ ██ ░░█████████  ██ █████   █████       ░░███      ░░████████   ███████████ █████  ░░█████
░░░░░   ░░░░░ ░░   ░░░░░░░░░  ░░ ░░░░░   ░░░░░         ░░░        ░░░░░░░░   ░░░░░░░░░░░ ░░░░░    ░░░░░
""",
    )
    print()
    print(c("                ╔" + "═" * (WIDTH - 2) + "╗", C.CYAN))
    print(
        c("                ║", C.CYAN)
        + c(
            " V1.6 - Network Vulnerability Scanner".center(WIDTH - 2),
            C.BOLD + C.CYAN,
        )
        + c("║", C.CYAN)
    )
    print(
        c("                ║", C.CYAN)
        + c(
            " Target == IP or DOMAIN (ex : google.com / 8.8.8.8)".center(
                WIDTH - 2
            ),
            C.DIM,
        )
        + c("║", C.CYAN)
    )
    print(c("                ╚" + "═" * (WIDTH - 2) + "╝", C.CYAN))
    print()

def severity_color(count):
    if count == 0:
        return C.GREEN
    if count < 5:
        return C.YELLOW
    return C.RED
def display_web_findings(findings):
    if not findings:
        empty("No basic web security issue detected")
        return
    print()
    warn(
        f"{c(len(findings), C.BOLD + C.RED)} "
        f"web security finding(s) discovered"
    )
    print()
    severity_colors = {
        "CRITICAL": C.RED,
        "HIGH": C.RED,
        "MEDIUM": C.YELLOW,
        "LOW": C.GREEN,
        "INFO": C.CYAN,
        "UNKNOWN": C.GRAY,
    }
    for finding in findings:
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        severity_color_value = severity_colors.get(
            severity,
            C.GRAY,
        )
        print(
            f"  {c('┌─', C.GRAY)} "
            f"{c(finding.get('id', 'UNKNOWN'), C.BOLD + severity_color_value)}"
        )
        print(
            f"  {c('│', C.GRAY)}  "
            f"Title          : "
            f"{finding.get('title', 'Unknown')}"
        )
        print(
            f"  {c('│', C.GRAY)}  "
            f"Severity       : "
            f"{c(severity, severity_color_value)}"
        )
        print(
            f"  {c('│', C.GRAY)}  "
            f"Confidence     : "
            f"{finding.get('confidence', 'UNKNOWN')}"
        )
        print(
            f"  {c('│', C.GRAY)}  "
            f"Category       : "
            f"{finding.get('category', 'Unknown')}"
        )

        classification = classify_web_finding(
            finding
        )

        print(
            f"  {c('│', C.GRAY)}  "
            f"Type           : "
            f"{classification}"
        )

        verification = str(
            finding.get(
                "verification",
                "OBSERVED",
            )
        ).upper()

        verification_color = (
            C.GREEN
            if verification == "CONFIRMED"
            else C.CYAN
            if verification == "OBSERVED"
            else C.YELLOW
        )

        print(
            f"  {c('│', C.GRAY)}  "
            f"Verification   : "
            f"{c(verification, verification_color)}"
        )
        print(
            f"  {c('│', C.GRAY)}  "
            f"URL            : "
            f"{c(finding.get('url', 'Unknown'), C.CYAN)}"
        )
        print(
            f"  {c('│', C.GRAY)}  "
            f"Evidence       : "
            f"{finding.get('evidence', 'None')}"
        )
        print(
            f"  {c('└─', C.GRAY)}  "
            f"Recommendation : "
            f"{finding.get('recommendation', 'None')}"
        )
        print()


def merge_technologies(technologies):
    merged={}
    confidence_order={
        "LOW":1,
        "MEDIUM":2,
        "HIGH":3
    }

    for technology in technologies:
        if not isinstance(technology,dict):
            continue

        name=str(
            technology.get("name")
            or technology.get("product")
            or ""
        ).strip()

        if not name:
            continue

        key=name.casefold()

        candidate=technology.copy()
        candidate["name"]=name

        candidate_version=str(
            candidate.get("version")
            or ""
        ).strip()

        if not candidate_version:
            candidate["version"]=None

        candidate_evidence=candidate.get(
            "evidence",
            []
        )

        if isinstance(candidate_evidence,str):
            candidate_evidence=[
                candidate_evidence
            ]

        elif not isinstance(
            candidate_evidence,
            list
        ):
            candidate_evidence=[]

        candidate["evidence"]=[
            str(item)
            for item in candidate_evidence
            if str(item).strip()
        ]

        current=merged.get(key)

        if current is None:
            merged[key]=candidate
            continue

        current_version=str(
            current.get("version")
            or ""
        ).strip()

        new_version=str(
            candidate.get("version")
            or ""
        ).strip()

        if new_version and not current_version:
            current["version"]=new_version

        elif (
            new_version
            and current_version
            and new_version!=current_version
        ):
            alternate_versions=current.setdefault(
                "alternate_versions",
                []
            )

            if new_version not in alternate_versions:
                alternate_versions.append(
                    new_version
                )

        current_confidence=str(
            current.get("confidence")
            or "LOW"
        ).upper()

        new_confidence=str(
            candidate.get("confidence")
            or "LOW"
        ).upper()

        if confidence_order.get(
            new_confidence,
            0
        )>confidence_order.get(
            current_confidence,
            0
        ):
            current["confidence"]=new_confidence

        if (
            current.get("port") is None
            and candidate.get("port") is not None
        ):
            current["port"]=candidate.get(
                "port"
            )

        current_evidence=current.setdefault(
            "evidence",
            []
        )

        if isinstance(current_evidence,str):
            current_evidence=[
                current_evidence
            ]
            current["evidence"]=current_evidence

        for evidence in candidate.get(
            "evidence",
            []
        ):
            if evidence not in current_evidence:
                current_evidence.append(
                    evidence
                )

        current_sources=[
            source.strip()
            for source in str(
                current.get("source")
                or ""
            ).split(",")
            if source.strip()
        ]

        candidate_sources=[
            source.strip()
            for source in str(
                candidate.get("source")
                or ""
            ).split(",")
            if source.strip()
        ]

        for source in candidate_sources:
            if source not in current_sources:
                current_sources.append(source)

        if current_sources:
            current["source"]=",".join(
                current_sources
            )

        if (
            not current.get("service")
            and candidate.get("service")
        ):
            current["service"]=candidate.get(
                "service"
            )

        if (
            not current.get("extra")
            and candidate.get("extra")
        ):
            current["extra"]=candidate.get(
                "extra"
            )

    return sorted(
        merged.values(),
        key=lambda technology:(
            str(
                technology.get("name")
                or ""
            ).casefold(),
            str(
                technology.get("version")
                or ""
            )
        )
    )

def main():
    banner()
    target_input = input(
        f"  {c('[?]', C.MAGENTA)} Target: "
    ).strip()
    if not target_input:
        print()
        error("Target cannot be empty")
        return

    profile_input = input(
        f"  {c('[?]', C.MAGENTA)} Profile [FAST/NORMAL/DEEP] (NORMAL): "
    ).strip().upper()

    scan_profile = get_profile(
        profile_input or "NORMAL"
    )

    info(
        f"Scan profile: {scan_profile.name} - {scan_profile.description}"
    )

    target = build_target(target_input)
    if target is None:
        print()
        error("Invalid or unresolved target")
        return
    web_findings = []
    template_findings = []
    web_report = {}
    template_result = {}
    section("TARGET INFORMATION")
    status(
        "Original",
        target.original,
        C.BOLD,
    )
    status(
        "Resolved IP",
        target.ip,
        C.GREEN,
    )
    status(
        "Hostname",
        target.hostname if target.hostname else "Not found",
        C.RESET if target.hostname else C.DIM,
    )
    status(
        "Scan Target",
        target.scan_target,
    )
    section("DNS ENUMERATION")
    info("Scanning DNS records...")
    target.dns = scan_dns(
        target.scan_target
    )
    if not target.dns:
        empty("No DNS records found")
    else:
        for record_type, records in target.dns.items():
            print(
                f"\n  {c('├─', C.GRAY)} "
                f"{c(record_type, C.BOLD + C.MAGENTA)}"
            )
            if not records:
                print(
                    f"  {c('│', C.GRAY)}  "
                    f"{c('└─ No records found', C.DIM)}"
                )
                continue
            for index, record in enumerate(records):
                prefix = (
                    "└─"
                    if index == len(records) - 1
                    else "├─"
                )
                print(
                    f"  {c('│', C.GRAY)}  "
                    f"{c(prefix, C.GRAY)} "
                    f"{record}"
                )
    section("HTTP ANALYSIS")
    info("Scanning HTTP service...")
    http_results = scan_http(
        target.scan_target
    )
    if not http_results:
        target.http = None
        empty("HTTP scan failed")
    else:
        target.http = http_results
        status(
            "URL",
            target.http.get("url", "Unknown"),
            C.CYAN,
        )
        code = target.http.get(
            "status_code",
            "Unknown",
        )
        code_color = (
            C.GREEN
            if isinstance(code, int) and code < 400
            else C.YELLOW
        )
        status(
            "Status Code",
            code,
            code_color,
        )
    section("PORT & SERVICE DISCOVERY", "▣")
    info("Running Nmap scan...")
    try:
        target.nmap = scan_target(
            target.scan_target
        )
    except RuntimeError as err:
        print()
        error(f"Nmap scan failed: {err}")
        return
    if not target.nmap:
        empty("No open ports found")
    else:
        print()
        success(
            f"{c(len(target.nmap), C.BOLD)} "
            f"open service(s) discovered"
        )
        print()
        for port, service in target.nmap.items():
            print(
                f"  {c('┌─', C.GRAY)} "
                f"{c('PORT ' + str(port), C.BOLD + C.GREEN)}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Protocol : "
                f"{c(service.get('protocol', 'Unknown'), C.CYAN)}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Service  : "
                f"{c(service.get('service', 'Unknown'), C.CYAN)}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Product  : "
                f"{service.get('product', 'Unknown')}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Version  : "
                f"{service.get('version', 'Unknown')}"
            )
            print(
                f"  {c('└─', C.GRAY)}  "
                f"Extra    : "
                f"{c(service.get('extra', 'Unknown'), C.DIM)}"
            )
            print()
    section("TECHNOLOGY FINGERPRINTING")

    target.technologies = fingerprint_nmap(
        target.nmap
    )

    if target.http:
        http_technologies = fingerprint_http(
            target.http
        )

        target.technologies.extend(
            http_technologies
        )

        web_url = target.http.get("url")

        if web_url:
            info("Detecting web technologies...")

            try:
                web_technologies = detect_web_technologies(
                    web_url,
                    verbose=False
                )

                target.technologies.extend(
                    web_technologies
                )

            except Exception as err:
                warn(
                    f"Web technology detection failed: {err}"
                )

    target.technologies = merge_technologies(
        target.technologies
    )

    try:
        target.technologies = enrich_technologies(
            target.technologies,
            (
                target.http.get("url")
                if target.http
                else None
            ),
        )
    except Exception as err:
        warn(
            f"Technology intelligence enrichment failed: {err}"
        )

    if not target.technologies:
        empty("No technologies identified")

    else:
        print()

        success(
            f"{c(len(target.technologies), C.BOLD)} "
            f"technology(s) detected"
        )

        print()

        for technology in target.technologies:
            name = technology.get(
                "name",
                "Unknown"
            )

            version = (
                technology.get("version")
                or "Unknown"
            )

            port = technology.get("port")

            port_info = (
                f"Port {port}"
                if port
                else "No port"
            )

            confidence = str(
                technology.get(
                    "confidence",
                    ""
                )
            ).upper()

            source = str(
                technology.get(
                    "source",
                    "Unknown"
                )
            )

            print(
                f"  {c('┌─', C.GRAY)} "
                f"{c(name, C.BOLD + C.CYAN)}"
            )

            print(
                f"  {c('│', C.GRAY)}  "
                f"Version    : "
                f"{c(version, C.YELLOW)}"
            )

            print(
                f"  {c('│', C.GRAY)}  "
                f"Port       : "
                f"{port_info}"
            )

            print(
                f"  {c('│', C.GRAY)}  "
                f"Source     : "
                f"{source}"
            )

            if confidence:
                confidence_color = (
                    C.GREEN
                    if confidence == "HIGH"
                    else C.YELLOW
                    if confidence == "MEDIUM"
                    else C.GRAY
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Confidence : "
                    f"{c(confidence, confidence_color)}"
                )

            confidence_score = technology.get(
                "confidence_score"
            )

            if confidence_score is not None:
                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Intel Score : "
                    f"{confidence_score}/100"
                )

            version_confidence = str(
                technology.get(
                    "version_confidence",
                    ""
                )
            ).upper()

            if version_confidence:
                version_conf_color = (
                    C.GREEN
                    if version_confidence == "HIGH"
                    else C.YELLOW
                    if version_confidence == "MEDIUM"
                    else C.GRAY
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Version Conf: "
                    f"{c(version_confidence, version_conf_color)}"
                )

            if technology.get(
                "version_conflict"
            ):
                print(
                    f"  {c('│', C.GRAY)}  "
                    f"{c('Version conflict detected', C.YELLOW)}"
                )

            version_candidates = technology.get(
                "version_candidates",
                [],
            )

            if version_candidates:
                candidate_text = ", ".join(
                    str(item.get("version"))
                    for item in version_candidates[:3]
                    if item.get("version")
                )

                if candidate_text:
                    print(
                        f"  {c('│', C.GRAY)}  "
                        f"Version Cand: "
                        f"{candidate_text}"
                    )

            aliases = technology.get(
                "aliases",
                [],
            )

            if aliases:
                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Aliases    : "
                    f"{', '.join(aliases[:5])}"
                )

            evidence = technology.get(
                "evidence",
                []
            )

            if isinstance(evidence, str):
                evidence = [evidence]

            if evidence:
                displayed_evidence = evidence[:3]

                for index, item in enumerate(
                    displayed_evidence
                ):
                    prefix = (
                        "Evidence   : "
                        if index == 0
                        else "             "
                    )

                    print(
                        f"  {c('│', C.GRAY)}  "
                        f"{prefix}"
                        f"{str(item)[:160]}"
                    )

                hidden_count = (
                    len(evidence)
                    - len(displayed_evidence)
                )

                if hidden_count > 0:
                    print(
                        f"  {c('│', C.GRAY)}  "
                        f"             "
                        f"{c(f'+{hidden_count} other evidence(s)', C.DIM)}"
                    )

            alternate_versions = technology.get(
                "alternate_versions",
                []
            )

            if alternate_versions:
                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Other versions : "
                    f"{', '.join(alternate_versions)}"
                )

            print(
                f"  {c('└─', C.GRAY)}"
            )

            print()

    if target.http:
        web_url = target.http.get("url")

        if web_url:
            section("WEB SECURITY ANALYSIS", "◆")

            web_report = scan_web(
                web_url,
                profile=scan_profile.name,
            )

            web_findings = web_report.get(
                "findings",
                [],
            )

            for skipped in web_report.get(
                "skipped_checks",
                [],
            ):
                info(
                    f"Skipped web check: "
                    f"{skipped.get('name', 'Unknown')} - "
                    f"{skipped.get('reason', 'no reason')}"
                )

            display_web_findings(
                web_findings
            )

        else:
            section("WEB SECURITY ANALYSIS", "◆")
            empty("Web checks skipped because no HTTP URL was returned")

    else:
        section("WEB SECURITY ANALYSIS", "◆")
        empty("Web checks skipped because no HTTP service was detected")
    section("TEMPLATE SECURITY ANALYSIS", "◇")

    if target.http and target.http.get("url"):
        template_result = run_templates(
            target.http.get("url"),
            "templates",
            verbose=True,
            technologies=target.technologies,
            profile=scan_profile.name,
            base_status=(
                web_report.get("status_code")
                if web_report
                else target.http.get("status_code")
            ),
        )

        template_findings = template_result.get(
            "findings",
            [],
        )

        template_stats = template_result.get(
            "stats",
            {},
        )

        if template_findings:
            print()

            warn(
                f"{c(len(template_findings), C.BOLD + C.RED)} "
                f"template finding(s) matched"
            )

            print()

            for finding in template_findings:
                severity = str(
                    finding.get(
                        "severity",
                        "UNKNOWN",
                    )
                ).upper()

                severity_color_value = (
                    C.RED
                    if severity in {"CRITICAL", "HIGH"}
                    else C.YELLOW
                    if severity == "MEDIUM"
                    else C.GREEN
                    if severity == "LOW"
                    else C.CYAN
                )

                print(
                    f"  {c('┌─', C.GRAY)} "
                    f"{c(finding.get('id', 'UNKNOWN'), C.BOLD + severity_color_value)}"
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Title       : "
                    f"{finding.get('title', 'Unknown')}"
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Severity    : "
                    f"{c(severity, severity_color_value)}"
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Confidence  : "
                    f"{finding.get('confidence', 'UNKNOWN')}"
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Category    : "
                    f"{finding.get('category', 'Unknown')}"
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Verification: "
                    f"{finding.get('verification', 'OBSERVED')}"
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"URL         : "
                    f"{c(finding.get('url', 'Unknown'), C.CYAN)}"
                )

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Evidence    : "
                    f"{finding.get('evidence', 'None')}"
                )

                extracted = finding.get(
                    "extracted",
                    {},
                )

                if extracted:
                    compact_extracted = ", ".join(
                        f"{key}={','.join(values[:3])}"
                        for key, values in extracted.items()
                        if values
                    )

                    if compact_extracted:
                        print(
                            f"  {c('│', C.GRAY)}  "
                            f"Extracted   : "
                            f"{compact_extracted}"
                        )

                print(
                    f"  {c('└─', C.GRAY)}  "
                    f"Recommendation : "
                    f"{finding.get('recommendation', 'None')}"
                )

                print()

        else:
            success("No template matched")

        info(
            f"Templates: {template_stats.get('templates', 0)} | "
            f"Executed: {template_stats.get('executed', 0)} | "
            f"N/A: {template_stats.get('not_applicable', 0)} | "
            f"Skipped: {template_stats.get('skipped', 0)} | "
            f"Matched: {template_stats.get('matched', 0)} | "
            f"Errors: {template_stats.get('errors', 0)} | "
            f"Requests: {template_stats.get('executed_requests', 0)}/"
            f"{template_stats.get('request_budget', 0)} | "
            f"Duration: {template_stats.get('duration', 0)}s"
        )

        load_errors = template_result.get(
            "load_errors",
            [],
        )

        execution_errors = template_result.get(
            "execution_errors",
            [],
        )

        not_applicable_templates = template_result.get(
            "not_applicable",
            [],
        )

        skipped_templates = template_result.get(
            "skipped",
            [],
        )

        if load_errors:
            warn(
                f"{len(load_errors)} template loading error(s)"
            )

        if execution_errors:
            warn(
                f"{len(execution_errors)} template execution error(s)"
            )

    else:
        empty(
            "Template checks skipped because no HTTP service was detected"
        )

    section("RESULT CONSOLIDATION", "◎")

    consolidated = merge_findings(
        web_findings,
        template_findings,
    )

    consolidated_findings = consolidated.get(
        "findings",
        [],
    )

    duplicates_removed = consolidated.get(
        "duplicates_removed",
        0,
    )

    success(
        f"{len(web_findings) + len(template_findings)} raw finding(s) -> "
        f"{len(consolidated_findings)} unique finding(s)"
    )

    if duplicates_removed:
        info(
            f"{duplicates_removed} duplicate finding(s) merged across scanners"
        )

    section("CVE VULNERABILITY ANALYSIS")
    info("Searching vulnerability databases...")
    cve_result = scan_technology_cves_detailed(
        target.technologies
    )

    target.vulnerabilities = cve_result.get(
        "vulnerabilities",
        [],
    )

    cpe_diagnostics = cve_result.get(
        "diagnostics",
        [],
    )
    print()

    resolved_cpes = [
        item
        for item in cpe_diagnostics
        if item.get("status") == "RESOLVED"
    ]

    unresolved_cpes = [
        item
        for item in cpe_diagnostics
        if item.get("status") == "UNRESOLVED"
    ]

    skipped_cpes = [
        item
        for item in cpe_diagnostics
        if item.get("status") == "SKIPPED"
    ]

    success(
        f"CPE resolution: "
        f"{len(resolved_cpes)} resolved / "
        f"{len(unresolved_cpes)} unresolved / "
        f"{len(skipped_cpes)} skipped"
    )

    for diagnostic in cpe_diagnostics:
        status_value = diagnostic.get(
            "status",
            "UNKNOWN",
        )

        product_value = diagnostic.get(
            "product",
            "Unknown",
        )

        version_value = (
            diagnostic.get("version")
            or "Unknown"
        )

        mode_value = diagnostic.get(
            "mode",
            "-"
        )

        confidence_value = diagnostic.get(
            "confidence",
            "LOW",
        )

        if status_value == "RESOLVED":
            status_value_color = C.GREEN
        elif status_value == "UNRESOLVED":
            status_value_color = C.YELLOW
        else:
            status_value_color = C.GRAY

        print(
            f"  {c('├─', C.GRAY)} "
            f"{c(product_value, C.BOLD)} "
            f"{c(version_value, C.YELLOW)} "
            f"{c(status_value, status_value_color)} "
            f"{c(f'[{mode_value}]', C.DIM)} "
            f"{c(f'conf={confidence_value}', C.DIM)}"
        )

    if not target.vulnerabilities:
        print()
        success("No applicable CVEs found")
        info(
            "This does not mean that the target has no web vulnerabilities"
        )
    else:
        print()
        warn(
            f"{c(len(target.vulnerabilities), C.BOLD + C.RED)} "
            f"applicable CVE(s) found"
        )
        print()
        severity_colors = {
            "CRITICAL": C.RED,
            "HIGH": C.RED,
            "MEDIUM": C.YELLOW,
            "LOW": C.GREEN,
            "UNKNOWN": C.GRAY,
        }
        for vulnerability in target.vulnerabilities:
            cve = vulnerability.get(
                "cve",
                {},
            )
            cve_id = cve.get(
                "id",
                "Unknown",
            )
            severity = str(
                cve.get(
                    "severity",
                    "UNKNOWN",
                )
            ).upper()
            cvss = cve.get(
                "cvss"
            )
            description = cve.get(
                "description",
                "No description available",
            )
            published = cve.get(
                "published",
                "Unknown",
            )
            severity_color_value = severity_colors.get(
                severity,
                C.GRAY,
            )
            print(
                f"  {c('┌─', C.GRAY)} "
                f"{c(cve_id, C.BOLD + C.RED)}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Technology : "
                f"{vulnerability.get('technology', 'Unknown')}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Version    : "
                f"{vulnerability.get('version', 'Unknown')}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Severity   : "
                f"{c(severity, severity_color_value)}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"CVSS       : "
                f"{c(str(cvss), severity_color_value)}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Port       : "
                f"{vulnerability.get('port', 'Unknown')}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"Published  : "
                f"{published}"
            )
            print(
                f"  {c('│', C.GRAY)}  "
                f"CPE        : "
                f"{c(vulnerability.get('cpe', 'Unknown'), C.DIM)}"
            )

            match_mode = vulnerability.get(
                "match_mode",
                "Unknown",
            )

            confidence_value = str(
                vulnerability.get(
                    "confidence",
                    "MEDIUM",
                )
            ).upper()

            print(
                f"  {c('│', C.GRAY)}  "
                f"Status     : "
                f"{c(vulnerability.get('status', 'APPLICABLE'), C.YELLOW)}"
            )

            print(
                f"  {c('│', C.GRAY)}  "
                f"Match      : "
                f"{match_mode}"
            )

            print(
                f"  {c('│', C.GRAY)}  "
                f"Confidence : "
                f"{confidence_value}"
            )

            cvss_version = cve.get("cvss_version")

            if cvss_version:
                print(
                    f"  {c('│', C.GRAY)}  "
                    f"CVSS Ver.  : "
                    f"{cvss_version}"
                )

            vector = cve.get("cvss_vector")

            if vector:
                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Vector     : "
                    f"{c(vector, C.DIM)}"
                )

            weaknesses = cve.get(
                "weaknesses",
                [],
            )

            if weaknesses:
                if isinstance(weaknesses, str):
                    weaknesses = [weaknesses]

                print(
                    f"  {c('│', C.GRAY)}  "
                    f"Weakness   : "
                    f"{', '.join(str(item) for item in weaknesses[:3])}"
                )

            print(
                f"  {c('└─', C.GRAY)}  "
                f"Description : "
                f"{description}"
            )
            print()
    section("SCAN COMPLETED")
    open_ports = (
        len(target.nmap)
        if target.nmap
        else 0
    )
    technologies = (
        len(target.technologies)
        if target.technologies
        else 0
    )
    web_count = (
        len(web_findings)
        if web_findings
        else 0
    )
    vulnerabilities = (
        len(target.vulnerabilities)
        if target.vulnerabilities
        else 0
    )
    status(
        "Target",
        target.original,
        C.BOLD,
    )
    status(
        "IP Address",
        target.ip,
        C.GREEN,
    )
    status(
        "Open Ports",
        open_ports,
        C.CYAN,
    )
    status(
        "Technologies",
        technologies,
        C.CYAN,
    )
    status(
        "Web Findings",
        web_count,
        severity_color(web_count),
    )

    status(
        "Template Matches",
        len(template_findings),
        severity_color(len(template_findings)),
    )

    status(
        "Unique Findings",
        len(consolidated_findings),
        severity_color(len(consolidated_findings)),
    )

    status(
        "Duplicates Merged",
        duplicates_removed,
        C.CYAN,
    )

    status(
        "Scan Profile",
        scan_profile.name,
        C.CYAN,
    )
    versioned_technologies = sum(
        1
        for technology in target.technologies
        if technology.get("version")
    )

    technology_count = len(
        target.technologies
    )

    version_coverage = (
        round(
            versioned_technologies
            / technology_count
            * 100,
            1,
        )
        if technology_count
        else 100.0
    )

    status(
        "Version Coverage",
        f"{versioned_technologies}/{technology_count} ({version_coverage}%)",
        C.GREEN
        if version_coverage >= 75
        else C.YELLOW
        if version_coverage >= 40
        else C.RED,
    )

    status("Applicable CVEs", vulnerabilities,
        severity_color(vulnerabilities),)

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
        profile=scan_profile.name,
    )

    status(
        "Scan Quality",
        scan_health.get("quality", "UNKNOWN"),
        C.GREEN
        if scan_health.get("quality") == "FULL"
        else C.YELLOW
        if scan_health.get("quality") in {"PARTIAL", "DEGRADED"}
        else C.RED,
    )

    status(
        "Coverage",
        f"{scan_health.get('coverage', 0)}%",
        C.GREEN
        if scan_health.get("coverage", 0) >= 85
        else C.YELLOW
        if scan_health.get("coverage", 0) >= 60
        else C.RED,
    )

    status(
        "Scan Confidence",
        scan_health.get("confidence", "LOW"),
        C.GREEN
        if scan_health.get("confidence") == "HIGH"
        else C.YELLOW
        if scan_health.get("confidence") == "MEDIUM"
        else C.RED,
    )

    status(
        "Checks Executed",
        scan_health.get("executed", 0),
        C.CYAN,
    )

    status(
        "Checks Skipped",
        scan_health.get("skipped", 0),
        C.YELLOW
        if scan_health.get("skipped", 0)
        else C.GREEN,
    )

    status(
        "Not Applicable",
        scan_health.get("not_applicable", 0),
        C.GRAY,
    )

    risk = build_risk_summary(
        consolidated_findings,
        target.vulnerabilities,
        unresolved_cpes,
    )

    risk_level = risk.get(
        "level",
        "UNKNOWN",
    )

    risk_score = risk.get(
        "score",
        0,
    )

    risk_color = (
        C.RED
        if risk_level in {"CRITICAL", "HIGH"}
        else C.YELLOW
        if risk_level in {"MEDIUM", "LOW"}
        else C.GREEN
    )

    if scan_health.get("risk_available"):
        status(
            "Risk Score",
            f"{risk_score}/100 ({risk_level})",
            risk_color,
        )
    else:
        status(
            "Risk Score",
            "N/A (insufficient scan coverage)",
            C.YELLOW,
        )

        for reason in scan_health.get(
            "reasons",
            [],
        )[:3]:
            info(
                f"Scan health: {reason}"
            )

    risk_components = risk.get(
        "components",
        {},
    )

    status(
        "Vulnerability Risk",
        f"{risk_components.get('vulnerability', 0)}/100",
        C.RED
        if risk_components.get("vulnerability", 0) >= 40
        else C.GREEN,
    )

    status(
        "Configuration Risk",
        f"{risk_components.get('configuration', 0)}/100",
        C.YELLOW
        if risk_components.get("configuration", 0) >= 20
        else C.GREEN,
    )

    status(
        "Exposure Risk",
        f"{risk_components.get('exposure', 0)}/100",
        C.YELLOW
        if risk_components.get("exposure", 0) >= 20
        else C.GREEN,
    )

    by_class = risk.get(
        "by_classification",
        {},
    )

    status(
        "Vulnerabilities",
        by_class.get("VULNERABILITY", 0),
        C.RED if by_class.get("VULNERABILITY", 0) else C.GREEN,
    )

    status(
        "Misconfigurations",
        by_class.get("MISCONFIGURATION", 0),
        C.YELLOW if by_class.get("MISCONFIGURATION", 0) else C.GREEN,
    )

    status(
        "Information",
        by_class.get("INFORMATION", 0),
        C.CYAN,
    )

    report = build_scan_report(
        target,
        web_findings,
        target.vulnerabilities,
        cpe_diagnostics,
        template_findings,
        consolidated_findings,
        scan_profile.name,
        scan_health,
    )

    try:
        report_path = save_json_report(
            report
        )

        status(
            "JSON Report",
            report_path,
            C.CYAN,
        )

        html_report_path = save_html_report(
            report
        )

        status(
            "HTML Report",
            html_report_path,
            C.CYAN,
        )
    except Exception as err:
        warn(
            f"Unable to save JSON report: {err}"
        )

    print()
    line("═", C.GREEN,)
    print(f"  {c('✔', C.GREEN)} "
        f"{c('Scan finished successfully.', C.BOLD + C.GREEN)}")
    line("═", C.GREEN,)
    print()

if __name__ == "__main__":
    main()