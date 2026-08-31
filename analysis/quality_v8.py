from __future__ import annotations
from copy import deepcopy
from collections import defaultdict
from typing import Any

SOURCE_WEIGHTS = {
    "nmap": 35, "header": 25, "html": 15,
    "javascript-analysis": 20, "signature-v6": 18,
    "cookie": 12, "unknown": 5,
}

def _sources(item: dict[str, Any]) -> set[str]:
    return {x.strip() for x in str(item.get("source") or "unknown").split(",") if x.strip()}

def score_technology(item: dict[str, Any]) -> dict[str, Any]:
    tech=deepcopy(item)
    sources=_sources(tech)
    evidence=tech.get("evidence") or []
    if isinstance(evidence,str): evidence=[evidence]
    score=sum(SOURCE_WEIGHTS.get(s,10) for s in sources)
    conf=str(tech.get("confidence") or "LOW").upper()
    score += 20 if conf=="HIGH" else 10 if conf=="MEDIUM" else 0
    version=str(tech.get("version") or "").strip()
    if version: score += 20
    score += min(20,len(evidence)*5)
    score=min(100,score)
    tech["quality_score"]=score
    tech["version_confidence_v8"]=("HIGH" if version and score>=80 else "MEDIUM" if version and score>=60 else "LOW" if version else "UNKNOWN")
    tech["quality_reason"]={"sources":sorted(sources),"evidence_count":len(evidence),"version_present":bool(version),"base_confidence":conf}
    tech["cpe_eligible_v8"]=bool(version) and score>=60
    return tech

def enrich_technologies_v8(items: list[dict[str,Any]]) -> list[dict[str,Any]]:
    return [score_technology(x) for x in items or []]

def correlate(*, endpoints, technologies, vulnerabilities, findings):
    by_port=defaultdict(list)
    for tech in technologies or []:
        if tech.get("port") is not None: by_port[str(tech.get("port"))].append(tech)
    rows=[]
    for endpoint in endpoints or []:
        port=endpoint.get("port")
        techs=by_port.get(str(port),[]) if port is not None else technologies or []
        names={str(t.get("name") or "").casefold() for t in techs}
        rel_findings=[f for f in findings or [] if str(f.get("url") or "")==str(endpoint.get("url") or "") or (port is not None and str(f.get("port") or "")==str(port))]
        rel_vulns=[v for v in vulnerabilities or [] if str(v.get("technology") or "").casefold() in names]
        rows.append({"endpoint":endpoint,"technologies":techs[:8],"findings":rel_findings[:20],"vulnerabilities":rel_vulns[:20]})
    return rows

def prioritize_finding(finding: dict[str,Any]) -> dict[str,Any]:
    item=deepcopy(finding)
    severity=str(item.get("severity") or "INFO").upper()
    confidence=str(item.get("confidence") or "LOW").upper()
    verification=str(item.get("verification_state") or item.get("verification") or "DETECTED").upper()
    score={"CRITICAL":90,"HIGH":75,"MEDIUM":55,"LOW":30,"INFO":10}.get(severity,10)
    reasons=[f"Severity={severity}"]
    if confidence=="HIGH": score+=8; reasons.append("High confidence")
    elif confidence=="MEDIUM": score+=4; reasons.append("Medium confidence")
    if verification=="CONFIRMED": score+=12; reasons.append("Confirmed")
    elif verification=="LIKELY": score+=6; reasons.append("Likely")
    elif verification=="FALSE_POSITIVE": score=0; reasons.append("False positive")
    if str(item.get("url") or "").startswith(("http://","https://")): score+=4; reasons.append("Reachable web surface")
    score=max(0,min(100,score))
    priority="P1" if score>=85 else "P2" if score>=65 else "P3" if score>=40 else "P4"
    item.update(priority_score=score,priority=priority,priority_reason=reasons)
    return item

def prioritize_findings(findings):
    return sorted((prioritize_finding(x) for x in findings or []), key=lambda x:x.get("priority_score",0), reverse=True)
