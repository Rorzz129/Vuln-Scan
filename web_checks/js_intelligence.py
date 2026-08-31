from __future__ import annotations
from typing import Any
from urllib.parse import urljoin, urlsplit
import hashlib, re
from web_checks.common import WebScanContext, ensure_context, cached_request, response_text, make_finding
from web_checks.javascript import extract_script_sources

MAX_SCRIPTS=12; MAX_SCRIPT_SIZE=750000
ENDPOINTS=(re.compile(r'''["'](/api/[A-Za-z0-9_./?=&%{}:-]+)["']''',re.I), re.compile(r'''["'](/graphql(?:[/?][A-Za-z0-9_./?=&%{}:-]*)?)["']''',re.I), re.compile(r'''["'](/v[0-9]+/[A-Za-z0-9_./?=&%{}:-]+)["']''',re.I))
WS_RE=re.compile(r'''wss?://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9_./?=&%{}:-]*)?''',re.I)
SM_RE=re.compile(r'''(?:\/\/[#@]\s*sourceMappingURL\s*=\s*|\/\*#\s*sourceMappingURL\s*=\s*)([^\s*]+)''',re.I)
SECRETS={'AWS access key identifier':re.compile(r'\bAKIA[0-9A-Z]{16}\b'),'Google API key-like token':re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'),'Private key marker':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')}
GENERIC=re.compile(r'''(?i)\b(?:api[_-]?key|secret|token|client[_-]?secret)\b\s*[:=]\s*["']([^"']{20,})["']''')

def _origin(u):
    p=urlsplit(u); return (p.scheme.lower(),(p.hostname or '').lower(),p.port or (443 if p.scheme=='https' else 80))
def _fp(v): return hashlib.sha256(v.encode('utf-8',errors='ignore')).hexdigest()[:12]

def check_js_intelligence(value:str|WebScanContext)->list[dict[str,Any]]:
    ctx,own=ensure_context(value)
    try:
        if ctx.degraded: return []
        html=response_text(ctx.response,1200000); endpoints=[]; websockets=[]; maps=[]; secrets=[]; analyzed=0
        for script in extract_script_sources(html,ctx.url)[:MAX_SCRIPTS]:
            if _origin(script)!=_origin(ctx.url): continue
            try: r=cached_request(ctx.session,'GET',script,timeout=(2.5,5.0))
            except Exception: continue
            if r.status_code>=400: continue
            content=response_text(r,MAX_SCRIPT_SIZE)
            if not content: continue
            analyzed+=1
            for pattern in ENDPOINTS:
                for m in pattern.findall(content):
                    u=urljoin(ctx.url,m)
                    if u not in endpoints: endpoints.append(u)
            for m in WS_RE.findall(content):
                if m not in websockets: websockets.append(m)
            for m in SM_RE.findall(content):
                u=urljoin(script,m.strip())
                if u not in maps: maps.append(u)
            for name,pattern in SECRETS.items():
                for m in pattern.findall(content): secrets.append({'type':name,'fingerprint':_fp(str(m)),'script':script})
            for m in GENERIC.findall(content): secrets.append({'type':'Generic secret-like value','fingerprint':_fp(m),'script':script})
        findings=[]
        if endpoints or websockets:
            f=make_finding('WEB-JS-001','Client-side API endpoints discovered','INFO','JavaScript Intelligence',ctx.url,
                f'Analyzed {analyzed} same-origin JavaScript file(s); discovered {len(endpoints)} API endpoint(s) and {len(websockets)} WebSocket endpoint(s).',
                'Review client-side routes as additional application surface and validate authorization during the authorized assessment.','MEDIUM')
            f['metadata']={'api_endpoints':endpoints[:150],'websocket_endpoints':websockets[:50],'scripts_analyzed':analyzed}; findings.append(f)
        if maps:
            f=make_finding('WEB-JS-002','JavaScript source map references discovered','LOW','Information Disclosure',ctx.url,
                f'{len(maps)} source map reference(s) were observed in production JavaScript.','Review whether production source maps should be publicly available.','HIGH')
            f['metadata']={'source_maps':maps[:50]}; findings.append(f)
        if secrets:
            uniq=[]; seen=set()
            for item in secrets:
                key=(item['type'],item['fingerprint'])
                if key not in seen: seen.add(key); uniq.append(item)
            f=make_finding('WEB-JS-003','Secret-like values detected in client-side JavaScript','HIGH','Information Disclosure',ctx.url,
                f'{len(uniq)} unique secret-like value(s) were detected. Raw values are intentionally omitted.','Verify whether the values are sensitive credentials; rotate exposed secrets and remove confidential values from client-side code.','MEDIUM')
            f['metadata']={'secret_fingerprints':uniq[:50]}; findings.append(f)
        return findings
    finally:
        if own: ctx.session.close()
