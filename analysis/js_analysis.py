from urllib.parse import urljoin,urlsplit
import re
from web_checks.common import create_session,cached_request,response_text
from web_checks.javascript import extract_script_sources
REL_API=re.compile(r"['\"](/(?:api|graphql|v[0-9]+)[A-Za-z0-9_./?=&%{}:-]*)['\"]",re.I)
ABS_API=re.compile(r'https?://[A-Za-z0-9.-]+(?::[0-9]+)?/(?:api|graphql|v[0-9]+)(?:/[A-Za-z0-9_./?=&%{}:-]*)?',re.I)
WS=re.compile(r'wss?://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9_./?=&%{}:-]*)?',re.I)
PARAM=re.compile(r'[?&]([A-Za-z_][A-Za-z0-9_-]{1,50})=',re.I)
SMAP=re.compile(r'sourceMappingURL\s*=\s*([^\s*]+)',re.I)
TECH={'React':('react','__react'),'Angular':('angular','ng-version'),'Vue.js':('vue','__vue__'),'Next.js':('_next/static','__next_data__'),'Nuxt':('_nuxt/','__nuxt__'),'jQuery':('jquery',),'Bootstrap':('bootstrap',)}
def origin(url):
    p=urlsplit(url); return (p.scheme,p.hostname,p.port or (443 if p.scheme=='https' else 80))
def analyze_javascript(base_url,html,max_scripts=12):
    session=create_session(); scripts=[]; apis=[]; webs=[]; params=set(); maps=[]; tech={}
    try:
        for script in extract_script_sources(html or '',base_url)[:max_scripts]:
            if origin(script)!=origin(base_url): continue
            try: r=cached_request(session,'GET',script,timeout=(2.5,5.0))
            except Exception: continue
            if r.status_code>=400: continue
            body=response_text(r,limit=800000); scripts.append({'url':script,'status':r.status_code,'size':len(body)})
            for m in REL_API.findall(body):
                u=urljoin(base_url,m)
                if u not in apis: apis.append(u)
            for u in ABS_API.findall(body):
                if u not in apis: apis.append(u)
            for u in WS.findall(body):
                if u not in webs: webs.append(u)
            params.update(PARAM.findall(body))
            for m in SMAP.findall(body):
                u=urljoin(script,m.strip())
                if u not in maps: maps.append(u)
            low=body.casefold()
            for name,sigs in TECH.items():
                score=sum(1 for s in sigs if s.casefold() in low)
                if score: tech[name]=max(tech.get(name,0),score)
        return {'scripts':scripts,'api_endpoints':apis[:200],'websocket_endpoints':webs[:100],'parameters':sorted(params),'source_maps':maps[:100],'technologies':[{'name':n,'version':None,'source':'javascript-analysis','confidence':'HIGH' if s>=2 else 'MEDIUM','evidence':[f'JavaScript signature score={s}']} for n,s in sorted(tech.items())]}
    finally: session.close()
