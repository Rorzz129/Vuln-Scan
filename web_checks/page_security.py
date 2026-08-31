from __future__ import annotations
from typing import Any
import re
from web_checks.common import WebScanContext, ensure_context, response_text, make_finding
HTTP_RE=re.compile(r'''(?:src|href|action)=["']http://[^"']+["']''',re.I)
PASSWORD_FORM=re.compile(r'''<form\b[^>]*>.*?<input\b[^>]*type=["']password["'][^>]*>.*?</form>''',re.I|re.S)

def check_page_security(value:str|WebScanContext)->list[dict[str,Any]]:
    ctx,own=ensure_context(value)
    try:
        if ctx.degraded: return []
        html=response_text(ctx.response,1500000); out=[]
        if ctx.url.lower().startswith('https://'):
            hits=HTTP_RE.findall(html)
            if hits:
                out.append(make_finding('WEB-PAGE-001','Mixed HTTP content referenced from HTTPS page','MEDIUM','Transport Security',ctx.url,
                    f'{len(hits)} HTTP resource/form reference(s) were observed on an HTTPS page.','Serve all resources and form destinations over HTTPS.','HIGH'))
        if ctx.url.lower().startswith('http://') and PASSWORD_FORM.search(html):
            out.append(make_finding('WEB-PAGE-002','Authentication form exposed over HTTP','HIGH','Transport Security',ctx.url,
                'A form containing a password field was observed on a plain HTTP page.','Serve authentication pages exclusively over HTTPS.','HIGH'))
        return out
    finally:
        if own: ctx.session.close()
