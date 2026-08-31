from copy import deepcopy
WEIGHTS={'nmap':40,'header':30,'html':20,'javascript-analysis':20,'unknown':5}
def score_technology(t):
    x=deepcopy(t); sources={s.strip() for s in str(x.get('source') or 'unknown').split(',') if s.strip()}; score=sum(WEIGHTS.get(s,10) for s in sources); conf=str(x.get('confidence') or 'LOW').upper(); score+=20 if conf=='HIGH' else 10 if conf=='MEDIUM' else 0; version=str(x.get('version') or '').strip(); score+=20 if version else 0; ev=x.get('evidence') or []; ev=[ev] if isinstance(ev,str) else ev; score+=min(20,len(ev)*5); x['cpe_intel_score']=min(100,score); x['cpe_intel_reason']={'sources':sorted(sources),'confidence':conf,'version_present':bool(version),'evidence_count':len(ev)}; x['cpe_eligible']=x['cpe_intel_score']>=60 and bool(version); return x
def enrich_for_cpe(items): return [score_technology(x) for x in items or []]
