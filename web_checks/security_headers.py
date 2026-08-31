from __future__ import annotations
import re
from typing import Any
from web_checks.common import WebScanContext,ensure_context,make_finding

RULES={
    "content-security-policy":("WEB-HEADER-001","Content-Security-Policy header missing","MEDIUM","Deploy a restrictive Content-Security-Policy appropriate for the application."),
    "strict-transport-security":("WEB-HEADER-002","Strict-Transport-Security header missing","MEDIUM","Enable HSTS after confirming HTTPS is consistently available."),
    "x-content-type-options":("WEB-HEADER-003","X-Content-Type-Options header missing","LOW","Set X-Content-Type-Options: nosniff."),
    "referrer-policy":("WEB-HEADER-004","Referrer-Policy header missing","LOW","Define an appropriate Referrer-Policy."),
    "permissions-policy":("WEB-HEADER-005","Permissions-Policy header missing","INFO","Restrict browser features that the application does not require."),
}

def check_security_headers(value:str|WebScanContext)->list[dict[str,Any]]:
    ctx,own=ensure_context(value)
    findings=[]
    try:
        response=ctx.response
        headers={str(k).lower():str(v).strip() for k,v in response.headers.items()}
        if not ctx.degraded:
            for header,(fid,title,severity,recommendation) in RULES.items():
                if header=="strict-transport-security" and not response.url.lower().startswith("https://"):
                    continue
                if header not in headers:
                    findings.append(make_finding(fid,title,severity,"Security Headers",response.url,
                        f"HTTP response does not contain {header}.",recommendation,"HIGH"))
            csp=headers.get("content-security-policy","").lower()
            xfo=headers.get("x-frame-options","")
            if "frame-ancestors" not in csp and not xfo:
                findings.append(make_finding("WEB-HEADER-006","Clickjacking protection not detected","LOW",
                    "Security Headers",response.url,
                    "Neither CSP frame-ancestors nor X-Frame-Options was detected.",
                    "Use CSP frame-ancestors and/or a compatible X-Frame-Options policy.","HIGH"))
            if "'unsafe-eval'" in csp:
                findings.append(make_finding("WEB-HEADER-008","CSP allows unsafe-eval","MEDIUM",
                    "Security Headers",response.url,"Content-Security-Policy contains 'unsafe-eval'.",
                    "Remove 'unsafe-eval' unless it is strictly required.","HIGH"))
            hsts=headers.get("strict-transport-security","")
            match=re.search(r"max-age\s*=\s*(\d+)",hsts,re.I)
            if match and int(match.group(1))<2_592_000:
                findings.append(make_finding("WEB-HEADER-010","HSTS max-age is short","LOW",
                    "Security Headers",response.url,f"Strict-Transport-Security max-age={match.group(1)}.",
                    "Review whether a longer HSTS max-age is appropriate.","HIGH"))
        server=headers.get("server")
        if server:
            findings.append(make_finding("WEB-HEADER-011","Server software information disclosed","INFO",
                "Information Disclosure",response.url,f"Server: {server}",
                "Reduce unnecessary product/version disclosure in response headers.","HIGH"))
        powered_by=headers.get("x-powered-by")
        if powered_by:
            findings.append(make_finding("WEB-HEADER-012","Application technology disclosed","INFO",
                "Information Disclosure",response.url,f"X-Powered-By: {powered_by}",
                "Remove unnecessary framework or runtime disclosure headers.","HIGH"))
        return findings
    finally:
        if own:
            ctx.session.close()
