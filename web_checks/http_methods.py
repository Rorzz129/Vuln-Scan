from __future__ import annotations
from typing import Any
from web_checks.common import WebScanContext,ensure_context,make_finding,cached_request

RULES={
    "TRACE":("WEB-METHOD-001","HTTP TRACE method advertised","MEDIUM","Disable TRACE unless explicitly required."),
    "PUT":("WEB-METHOD-002","HTTP PUT method advertised","INFO","Ensure PUT endpoints require appropriate authentication and authorization."),
    "DELETE":("WEB-METHOD-003","HTTP DELETE method advertised","INFO","Ensure DELETE endpoints require appropriate authentication and authorization."),
    "CONNECT":("WEB-METHOD-004","HTTP CONNECT method advertised","MEDIUM","Disable CONNECT unless the service intentionally operates as a proxy."),
}

def check_http_methods(value:str|WebScanContext)->list[dict[str,Any]]:
    ctx,own=ensure_context(value);findings=[]
    try:
        if ctx.degraded:
            return findings
        response=cached_request(ctx.session,"OPTIONS",ctx.url)
        methods=set()
        for header in ("Allow","Access-Control-Allow-Methods"):
            for method in response.headers.get(header,"").split(","):
                method=method.strip().upper()
                if method:
                    methods.add(method)
        for method,(fid,title,severity,recommendation) in RULES.items():
            if method in methods:
                findings.append(make_finding(fid,title,severity,"HTTP Methods",response.url,
                    f"The server advertised {method} in an Allow/CORS methods response header.",
                    recommendation,"MEDIUM"))
        return findings
    finally:
        if own:
            ctx.session.close()
