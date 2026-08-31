import re
VAR=re.compile(r'\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}')
def render_value(value,variables):
    if isinstance(value,str): return VAR.sub(lambda m:str(variables.get(m.group(1),m.group(0))),value)
    if isinstance(value,list): return [render_value(v,variables) for v in value]
    if isinstance(value,dict): return {k:render_value(v,variables) for k,v in value.items()}
    return value
def technology_tags(technologies):
    tags=set()
    for t in technologies or []:
        name=str(t.get('name') or '').casefold()
        if name: tags.add(name)
        tags.update(str(a).casefold() for a in t.get('aliases') or [])
    return tags
def template_applicable(template,technologies):
    tags=technology_tags(technologies); req={str(x).casefold() for x in getattr(template,'requires_tags',[])}; exc={str(x).casefold() for x in getattr(template,'excludes_tags',[])}
    if req and not req.issubset(tags): return False,'required technology tags are missing'
    if exc and tags.intersection(exc): return False,'excluded technology tag matched'
    return True,''
