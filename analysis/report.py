from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import html

from analysis.risk import build_risk_summary, classify_web_finding


def build_scan_report(
    target: Any,
    web_findings: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    cpe_diagnostics: list[dict[str, Any]] | None = None,
    template_findings: list[dict[str, Any]] | None = None,
    consolidated_findings: list[dict[str, Any]] | None = None,
    scan_profile: str = "NORMAL",
    scan_health: dict[str, Any] | None = None,
) -> dict[str, Any]:
    enriched_web = []

    for finding in web_findings or []:
        item = dict(finding)
        item["classification"] = classify_web_finding(item)
        enriched_web.append(item)

    unresolved = [
        item
        for item in (cpe_diagnostics or [])
        if item.get("status") == "UNRESOLVED"
    ]

    risk_findings = consolidated_findings or enriched_web

    risk = build_risk_summary(
        risk_findings,
        vulnerabilities or [],
        unresolved,
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "original": getattr(target, "original", None),
            "ip": getattr(target, "ip", None),
            "hostname": getattr(target, "hostname", None),
            "scan_target": getattr(target, "scan_target", None),
        },
        "dns": getattr(target, "dns", None),
        "http": getattr(target, "http", None),
        "nmap": getattr(target, "nmap", None),
        "technologies": getattr(target, "technologies", None),
        "web_findings": enriched_web,
        "applicable_cves": vulnerabilities or [],
        "cpe_diagnostics": cpe_diagnostics or [],
        "template_findings": template_findings or [],
        "consolidated_findings": consolidated_findings or enriched_web,
        "scan_profile": scan_profile,
        "scan_health": scan_health or {},
        "risk": risk,
    }


def save_json_report(
    report: dict[str, Any],
    output_dir: str = "reports",
) -> str:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    raw_target = str(
        (report.get("target") or {}).get("original")
        or "target"
    )

    safe_target = "".join(
        char if char.isalnum() or char in "._-" else "_"
        for char in raw_target
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = directory / f"vulnscope_{safe_target}_{timestamp}.json"

    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    return str(path)


def _h(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))

def save_html_report(report: dict[str, Any], output_dir: str = "reports") -> str:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = report.get("target") or {}
    raw_target = str(target.get("original") or "target")
    safe_target = "".join(char if char.isalnum() or char in "._-" else "_" for char in raw_target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = directory / f"vulnscope_{safe_target}_{timestamp}.html"

    risk = report.get("risk") or {}
    scan_health = report.get("scan_health") or {}
    risk_display = (
        f"{risk.get('score', 0)}/100"
        if scan_health.get("risk_available", True)
        else "N/A"
    )
    findings = report.get("consolidated_findings") or report.get("web_findings") or []
    cves = report.get("applicable_cves") or []
    diagnostics = report.get("cpe_diagnostics") or []

    technologies = report.get("technologies") or []

    technology_rows = "".join(
        f"<tr><td>{_h(t.get('name'))}</td><td>{_h(t.get('version') or 'Unknown')}</td><td>{_h(t.get('confidence'))}</td><td>{_h(t.get('confidence_score',''))}</td><td>{_h(t.get('version_confidence',''))}</td><td>{_h(t.get('source'))}</td></tr>"
        for t in technologies
    ) or '<tr><td colspan="6">No technologies detected</td></tr>'

    finding_rows = "".join(
        f"<tr><td>{_h(f.get('id'))}</td><td>{_h(f.get('severity'))}</td><td>{_h(f.get('title'))}</td><td>{_h(f.get('url'))}</td><td>{_h(', '.join(f.get('sources') or [f.get('source','')]))}</td></tr>"
        for f in findings
    ) or '<tr><td colspan="5">No findings</td></tr>'

    cve_rows = "".join(
        f"<tr><td>{_h((v.get('cve') or {}).get('id'))}</td><td>{_h(v.get('technology'))}</td><td>{_h(v.get('version'))}</td><td>{_h((v.get('cve') or {}).get('severity'))}</td><td>{_h((v.get('cve') or {}).get('cvss'))}</td></tr>"
        for v in cves
    ) or '<tr><td colspan="5">No applicable CVEs</td></tr>'

    cpe_rows = "".join(
        f"<tr><td>{_h(d.get('product'))}</td><td>{_h(d.get('version'))}</td><td>{_h(d.get('status'))}</td><td>{_h(d.get('mode','-'))}</td><td>{_h(d.get('confidence'))}</td></tr>"
        for d in diagnostics
    ) or '<tr><td colspan="5">No CPE diagnostics</td></tr>'

    document = f'''<!doctype html>
<html><head><meta charset="utf-8"><title>VulnScope V1.6 - {_h(raw_target)}</title>
<style>
body{{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:28px}}h1,h2{{color:#58a6ff}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}}.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px}}.value{{font-size:26px;font-weight:700}}table{{width:100%;border-collapse:collapse;background:#161b22;margin-bottom:28px}}th,td{{padding:10px;border:1px solid #30363d;text-align:left;vertical-align:top}}th{{background:#21262d;color:#58a6ff}}small{{color:#8b949e}}code{{color:#79c0ff}}</style></head>
<body><h1>VulnScope V1.6</h1><small>Generated {_h(report.get('generated_at'))}</small>
<div class="grid"><div class="card">Target<div class="value">{_h(raw_target)}</div></div><div class="card">Risk<div class="value">{_h(risk_display)}</div>{_h(risk.get('level','UNKNOWN') if scan_health.get('risk_available', True) else 'INSUFFICIENT COVERAGE')}</div><div class="card">Coverage<div class="value">{_h(scan_health.get('coverage','?'))}%</div>{_h(scan_health.get('quality','UNKNOWN'))}</div><div class="card">Vulnerability Risk<div class="value">{_h((risk.get('components') or {}).get('vulnerability',0))}/100</div></div><div class="card">Configuration Risk<div class="value">{_h((risk.get('components') or {}).get('configuration',0))}/100</div></div><div class="card">Exposure Risk<div class="value">{_h((risk.get('components') or {}).get('exposure',0))}/100</div></div><div class="card">Findings<div class="value">{len(findings)}</div></div><div class="card">Applicable CVEs<div class="value">{len(cves)}</div></div></div>
<h2>Technology intelligence</h2><table><thead><tr><th>Technology</th><th>Version</th><th>Confidence</th><th>Intel Score</th><th>Version Confidence</th><th>Sources</th></tr></thead><tbody>{technology_rows}</tbody></table>
<h2>Consolidated findings</h2><table><thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>URL</th><th>Sources</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>CPE diagnostics</h2><table><thead><tr><th>Product</th><th>Version</th><th>Status</th><th>Mode</th><th>Confidence</th></tr></thead><tbody>{cpe_rows}</tbody></table>
<h2>Applicable CVEs</h2><table><thead><tr><th>CVE</th><th>Technology</th><th>Version</th><th>Severity</th><th>CVSS</th></tr></thead><tbody>{cve_rows}</tbody></table>
</body></html>'''
    path.write_text(document, encoding="utf-8")
    return str(path)


def save_markdown_report(report: dict, output_dir: str = "reports") -> str:
    from pathlib import Path
    from datetime import datetime
    import re

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    target = (report.get("target") or {}).get("original") or "target"
    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", str(target))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output / f"acr_vuln_{safe_target}_{stamp}.md"

    findings = (
        report.get("consolidated_findings")
        or report.get("findings")
        or []
    )

    lines = [
        "# A.C.R Vuln Pentest Report",
        "",
        f"**Target:** {target}",
        f"**Profile:** {report.get('profile', '-')}",
        "",
        "## Executive Summary",
        "",
        "Automated non-destructive reconnaissance and vulnerability analysis summary.",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No consolidated findings were recorded.")

    for index, finding in enumerate(findings, 1):
        lines.extend([
            f"### {index}. {finding.get('title', finding.get('id', 'Finding'))}",
            "",
            f"- Severity: **{finding.get('severity', 'UNKNOWN')}**",
            f"- Confidence: {finding.get('confidence', 'UNKNOWN')}",
            f"- Verification: {finding.get('verification', 'OBSERVED')}",
            f"- Category: {finding.get('category', '-')}",
            f"- URL: {finding.get('url', '-')}",
            "",
            "**Evidence**",
            "",
            str(finding.get("evidence") or "-"),
            "",
            "**Recommendation**",
            "",
            str(finding.get("recommendation") or "-"),
            "",
        ])

    lines.extend([
        "## Limitations",
        "",
        "Automated results should be manually validated before being treated as confirmed vulnerabilities.",
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def save_pentest_v2_report(result: dict, output_dir: str = "reports") -> str:
    from pathlib import Path
    from datetime import datetime
    import re
    out=Path(output_dir); out.mkdir(parents=True,exist_ok=True)
    target=(result.get("target") or {}).get("original") or "target"
    safe=re.sub(r"[^A-Za-z0-9._-]+","_",str(target)); path=out/f"acr_vuln_pentest_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    findings=result.get("findings") or []; assets=(result.get("assets") or {}).get("assets") or []; crawl=result.get("crawl") or {}; api=result.get("api_analysis") or {}; tls=result.get("tls") or {}; risk=result.get("risk") or {}
    lines=["# A.C.R Vuln Pentest Report V2","",f"**Target:** {target}",f"**Risk Score:** {risk.get('score','N/A')}","","## Executive Summary","","Non-destructive reconnaissance and vulnerability analysis summary.","","## Methodology","","Asset discovery, crawling, JS/API/Auth analysis, technology fingerprinting, safe templates, CPE/CVE correlation, TLS inspection and finding verification.","","## Discovered Surface","",f"- Assets: {len(assets)}",f"- Crawled pages: {len(crawl.get('pages') or [])}",f"- Forms: {len(crawl.get('forms') or [])}",f"- API endpoints: {api.get('endpoint_count',0)}",f"- API types: {', '.join(api.get('types') or []) or '-'}","","## TLS","",f"- Enabled: {tls.get('enabled',False)}",f"- Protocol: {tls.get('version','-')}",f"- Cipher: {tls.get('cipher','-')}",f"- Certificate days remaining: {tls.get('days_remaining','-')}","","## Findings",""]
    if not findings: lines.append("No findings were recorded.")
    for i,f in enumerate(findings,1):
        lines += [f"### {i}. {f.get('title',f.get('id','Finding'))}","",f"- Severity: **{f.get('severity','UNKNOWN')}**",f"- Verification: {f.get('verification_state',f.get('verification','DETECTED'))}",f"- Confidence: {f.get('confidence','UNKNOWN')}",f"- Category: {f.get('category','-')}",f"- URL: {f.get('url','-')}","","**Evidence**","",str(f.get('evidence') or '-'),"","**Verification rationale**","",str(f.get('verification_reason') or '-'),"","**Remediation**","",str(f.get('recommendation') or '-'),""]
    lines += ["## Technical Appendix","","### Assets",""] + [f"- {a.get('type')}: {a.get('value')} ({a.get('source')})" for a in assets[:200]] + ["","### Endpoint Intelligence",""] + [f"- {e.get('method')} {e.get('url')} [{', '.join(e.get('categories') or [])}]" for e in (result.get('endpoint_intel') or {}).get('endpoints',[])[:200]] + ["","## Limitations","","Automated results require manual validation. No destructive exploitation or credential guessing was performed.",""]
    path.write_text("\n".join(lines),encoding="utf-8"); return str(path)
