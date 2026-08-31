from __future__ import annotations

from socket import getaddrinfo
from typing import Any

COMMON_SUBDOMAINS = (
    "www", "api", "app", "dev", "test", "staging",
    "admin", "auth", "login", "cdn", "static", "status",
)

def _resolve(host: str) -> list[str]:
    results = []
    try:
        for entry in getaddrinfo(host, None):
            ip = str(entry[4][0])
            if ip not in results:
                results.append(ip)
    except Exception:
        pass
    return results

def discover_assets(
    target: str,
    dns_data: dict[str, Any] | None = None,
    deep: bool = False,
) -> dict[str, Any]:
    assets = []
    seen = set()

    def add(kind: str, value: str, source: str, metadata=None):
        key = (kind.casefold(), str(value).casefold())
        if not value or key in seen:
            return
        seen.add(key)
        assets.append({
            "type": kind,
            "value": str(value),
            "source": source,
            "metadata": metadata or {},
        })

    add("target", target, "input")

    for rtype, values in (dns_data or {}).items():
        values = values if isinstance(values, (list, tuple, set)) else [values]
        for value in values:
            if not value:
                continue
            text = str(value).strip()
            upper = str(rtype).upper()
            if upper in {"A", "AAAA"}:
                add("ip", text, f"dns:{upper}")
            elif upper in {"NS", "MX", "CNAME"}:
                add("hostname", text.split()[-1].rstrip("."), f"dns:{upper}")

    subdomains = []

    if deep and "." in target and not target.replace(".", "").isdigit():
        for prefix in COMMON_SUBDOMAINS:
            host = f"{prefix}.{target}"
            ips = _resolve(host)
            if not ips:
                continue
            subdomains.append(host)
            add("subdomain", host, "dns-resolution", {"ips": ips})
            for ip in ips:
                add("ip", ip, host)

    return {
        "assets": assets,
        "subdomains": subdomains,
        "count": len(assets),
    }
