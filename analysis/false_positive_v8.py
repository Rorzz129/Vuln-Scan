from __future__ import annotations
from copy import deepcopy

def reduce_false_positives(findings):
    output=[]
    for finding in findings or []:
        item=deepcopy(finding)
        evidence=str(item.get("evidence") or "").casefold()
        metadata=item.get("metadata") or {}
        reasons=[]
        if metadata.get("soft404_rejected") is False: reasons.append("Soft-404 validation failed")
        if "soft-404 similarity=1.00" in evidence: reasons.append("Response matched fallback content")
        if reasons:
            item["verification_state"]="FALSE_POSITIVE"
            item["verification_reason"]="; ".join(reasons)
        output.append(item)
    return output
