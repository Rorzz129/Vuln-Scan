from copy import deepcopy
def verify_finding(f):
    item=deepcopy(f); confidence=str(item.get('confidence') or 'LOW').upper(); explicit=str(item.get('verification') or '').upper(); evidence=str(item.get('evidence') or '').strip(); meta=item.get('metadata') or {}
    if explicit=='CONFIRMED': state='CONFIRMED'; reason='Originating check explicitly confirmed the condition.'
    elif meta.get('soft404_rejected') is False: state='FALSE_POSITIVE'; reason='Response validation indicates a fallback/soft-404.'
    elif confidence=='HIGH' and evidence: state='LIKELY'; reason='High-confidence evidence observed; no destructive exploitation was performed.'
    else: state='DETECTED'; reason='Relevant condition detected and requires manual validation.'
    item['verification_state']=state; item['verification_reason']=reason; return item
def verify_findings(items): return [verify_finding(x) for x in items or []]
