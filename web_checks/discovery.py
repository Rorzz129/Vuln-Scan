from __future__ import annotations
from typing import Any
from urllib.parse import urljoin, urlsplit
import re
from web_checks.common import WebScanContext, ensure_context, cached_request, response_text, make_finding

LINK_RE = re.compile(r'''(?:href|src|action)=["']([^"'#]+)["']''', re.I)
PASSWORD_RE = re.compile(r'''<input\b[^>]*type=["']password["'][^>]*>''', re.I)
MAX_LINKS = 250

def _origin(url: str):
    p = urlsplit(url)
    return (p.scheme.lower(), (p.hostname or '').lower(), p.port or (443 if p.scheme == 'https' else 80))

def _paths(html: str, base: str) -> list[str]:
    out=[]
    for raw in LINK_RE.findall(html or ''):
        full=urljoin(base, raw.strip())
        p=urlsplit(full)
        if p.scheme not in {'http','https'} or _origin(full)!=_origin(base): continue
        value=p.path or '/'
        if p.query: value += '?' + p.query
        if value not in out: out.append(value)
        if len(out)>=MAX_LINKS: break
    return out

def _robots(ctx: WebScanContext) -> dict[str,Any]:
    url=urljoin(ctx.origin+'/', 'robots.txt')
    try: r=cached_request(ctx.session,'GET',url,timeout=(2.5,4.0))
    except Exception: return {'url':url,'status':None,'paths':[],'sitemaps':[]}
    text=response_text(r,100000); paths=[]; sitemaps=[]
    if r.status_code==200:
        for line in text.splitlines():
            if ':' not in line: continue
            k,v=line.split(':',1); k=k.strip().casefold(); v=v.strip()
            if k in {'allow','disallow'} and v and v not in paths: paths.append(v)
            elif k=='sitemap' and v and v not in sitemaps: sitemaps.append(v)
    return {'url':r.url,'status':r.status_code,'paths':paths[:100],'sitemaps':sitemaps[:20]}

def _sitemap(ctx: WebScanContext, candidates:list[str]) -> dict[str,Any]:
    targets=[]
    for url in [*candidates, urljoin(ctx.origin+'/', 'sitemap.xml')]:
        if url not in targets: targets.append(url)
    discovered=[]; checked=[]
    for url in targets[:5]:
        try: r=cached_request(ctx.session,'GET',url,timeout=(2.5,4.0))
        except Exception: continue
        checked.append({'url':r.url,'status':r.status_code})
        if r.status_code!=200: continue
        for loc in re.findall(r'<loc>\s*(.*?)\s*</loc>', response_text(r,400000), re.I|re.S):
            loc=loc.strip()
            if loc and loc not in discovered: discovered.append(loc)
            if len(discovered)>=250: break
    return {'checked':checked,'urls':discovered}

def check_discovery(value:str|WebScanContext)->list[dict[str,Any]]:
    ctx,own=ensure_context(value)
    try:
        html=response_text(ctx.response,1500000)
        paths=_paths(html,ctx.url); robots=_robots(ctx); sitemap=_sitemap(ctx,robots.get('sitemaps',[]))
        finding=make_finding('WEB-DISCOVERY-001','Application surface discovered','INFO','Discovery',ctx.url,
            f"Observed {len(paths)} same-origin path(s), {len(robots.get('paths',[]))} robots.txt path(s), and {len(sitemap.get('urls',[]))} sitemap URL(s).",
            'Review discovered routes and include relevant authenticated areas in the authorized assessment scope.','HIGH')
        finding['metadata']={'same_origin_paths':paths,'robots':robots,'sitemap':sitemap}
        results=[finding]
        if ctx.url.lower().startswith('http://') and PASSWORD_RE.search(html):
            results.append(make_finding('WEB-FORM-001','Password form served over HTTP','HIGH','Transport Security',ctx.url,
                'A password input was observed on a page served over plain HTTP.','Serve authentication forms exclusively over HTTPS.','HIGH'))
        return results
    finally:
        if own: ctx.session.close()
