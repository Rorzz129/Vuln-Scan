def analyze_api(endpoint_map,crawl_result,js_result):
    kinds=set(); methods=set(); docs=[]; public=[]
    for item in endpoint_map.get('endpoints') or []:
        cats=set(item.get('categories') or []); url=item.get('url') or ''; method=item.get('method') or 'UNKNOWN'; methods.add(method)
        if 'graphql' in cats: kinds.add('GraphQL')
        if 'api' in cats: kinds.add('REST-like')
        if 'docs' in cats: docs.append(url)
        status=item.get('status')
        if status is not None and status<400 and cats & {'api','graphql','docs'}: public.append({'url':url,'method':method,'status':status,'reason':'Responded without an authentication context.'})
    params=set(crawl_result.get('parameters') or [])|set(js_result.get('parameters') or [])
    return {'types':sorted(kinds),'methods':sorted(methods),'documentation_endpoints':docs,'public_candidates':public,'endpoint_count':len(endpoint_map.get('endpoints') or []),'parameter_count':len(params)}
