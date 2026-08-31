from collections import Counter
from urllib.parse import urlsplit
import re
RULES=(('graphql',re.compile(r'/graphql(?:/|$)',re.I)),('api',re.compile(r'/(?:api|rest|v[0-9]+)(?:/|$)',re.I)),('admin',re.compile(r'/(?:admin|administrator|manage|dashboard)(?:/|$)',re.I)),('auth',re.compile(r'/(?:login|signin|signup|register|auth|logout|forgot|reset)(?:/|$)',re.I)),('upload',re.compile(r'/(?:upload|uploads|file|files|media)(?:/|$)',re.I)),('docs',re.compile(r'/(?:swagger|openapi|api-docs|docs)(?:/|$)',re.I)))
def classify_url(url):
    path=urlsplit(url).path or '/'; out=[n for n,r in RULES if r.search(path)]; return out or ['page']
def build_endpoint_map(crawl_result,js_result=None):
    rows=[]; seen=set()
    for page in crawl_result.get('pages') or []:
        u=page.get('url'); key=('GET',u)
        if not u or key in seen: continue
        seen.add(key); rows.append({'url':u,'method':'GET','status':page.get('status'),'categories':classify_url(u),'source':'crawler','parameters':[]})
    for form in crawl_result.get('forms') or []:
        u=form.get('action'); m=str(form.get('method') or 'GET').upper(); key=(m,u)
        if not u or key in seen: continue
        seen.add(key); rows.append({'url':u,'method':m,'status':None,'categories':classify_url(u),'source':'form','parameters':form.get('parameters') or []})
    for u in (js_result or {}).get('api_endpoints') or []:
        if ('JS',u) not in seen: seen.add(('JS',u)); rows.append({'url':u,'method':'UNKNOWN','status':None,'categories':classify_url(u),'source':'javascript','parameters':[]})
    for u in (js_result or {}).get('websocket_endpoints') or []:
        if ('WS',u) not in seen: seen.add(('WS',u)); rows.append({'url':u,'method':'WEBSOCKET','status':None,'categories':['websocket'],'source':'javascript','parameters':[]})
    c=Counter(cat for row in rows for cat in row['categories']); return {'endpoints':rows,'categories':dict(c),'count':len(rows)}
