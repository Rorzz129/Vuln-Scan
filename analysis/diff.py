from __future__ import annotations
from typing import Any

def _fkey(item: dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("id") or ""), str(item.get("url") or ""))

def _tkey(item: dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("name") or "").casefold(), str(item.get("version") or "Unknown"))

def compare_scans(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    if not previous:
        return {"available": False}

    pf = {_fkey(x): x for x in previous.get("findings") or []}
    cf = {_fkey(x): x for x in current.get("findings") or []}

    pp = {str(k): {"port": k, **(v if isinstance(v, dict) else {})} for k, v in (previous.get("nmap") or {}).items()}
    cp = {str(k): {"port": k, **(v if isinstance(v, dict) else {})} for k, v in (current.get("nmap") or {}).items()}

    pt = {_tkey(x): x for x in previous.get("technologies") or []}
    ct = {_tkey(x): x for x in current.get("technologies") or []}

    def cve_key(item):
        return str((item.get("cve") or {}).get("id") or "")

    pc = {cve_key(x): x for x in previous.get("vulnerabilities") or [] if cve_key(x)}
    cc = {cve_key(x): x for x in current.get("vulnerabilities") or [] if cve_key(x)}

    return {
        "available": True,
        "new_findings": [cf[k] for k in cf.keys() - pf.keys()],
        "resolved_findings": [pf[k] for k in pf.keys() - cf.keys()],
        "new_ports": [cp[k] for k in cp.keys() - pp.keys()],
        "closed_ports": [pp[k] for k in pp.keys() - cp.keys()],
        "new_technologies": [ct[k] for k in ct.keys() - pt.keys()],
        "removed_technologies": [pt[k] for k in pt.keys() - ct.keys()],
        "new_cves": [cc[k] for k in cc.keys() - pc.keys()],
        "resolved_cves": [pc[k] for k in pc.keys() - cc.keys()],
    }
