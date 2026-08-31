from datetime import datetime,timezone
from socket import create_connection
from ssl import create_default_context
from urllib.parse import urlsplit
def analyze_tls(url,timeout=5.0):
    p=urlsplit(url)
    if p.scheme!='https' or not p.hostname: return {'enabled':False,'reason':'Target is not HTTPS.'}
    host=p.hostname; port=p.port or 443; ctx=create_default_context()
    with create_connection((host,port),timeout=timeout) as sock:
        with ctx.wrap_socket(sock,server_hostname=host) as tls: cert=tls.getpeercert(); cipher=tls.cipher(); version=tls.version()
    subject={k:v for group in cert.get('subject',[]) for k,v in group}; issuer={k:v for group in cert.get('issuer',[]) for k,v in group}; sans=[v for k,v in cert.get('subjectAltName',[]) if k=='DNS']; days=None
    try: expiry=datetime.strptime(cert.get('notAfter'),'%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc); days=(expiry-datetime.now(timezone.utc)).days
    except Exception: pass
    findings=[]
    if days is not None and days<0: findings.append({'title':'TLS certificate expired','severity':'HIGH','evidence':f'Expired {-days} day(s) ago.'})
    elif days is not None and days<=30: findings.append({'title':'TLS certificate expires soon','severity':'LOW','evidence':f'Expires in {days} day(s).'})
    if version in {'TLSv1','TLSv1.1'}: findings.append({'title':'Legacy TLS protocol negotiated','severity':'MEDIUM','evidence':version})
    return {'enabled':True,'host':host,'port':port,'version':version,'cipher':cipher[0] if cipher else None,'days_remaining':days,'certificate':{'subject':subject,'issuer':issuer,'sans':sans,'not_before':cert.get('notBefore'),'not_after':cert.get('notAfter')},'findings':findings}
