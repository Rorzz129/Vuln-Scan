from __future__ import annotations
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
import fnmatch
@dataclass
class ScopePolicy:
    root: str
    allow_subdomains: bool=True
    allowed_cidrs: list[str]=field(default_factory=list)
    exclusions: list[str]=field(default_factory=list)
    def root_host(self):
        v=self.root.strip(); v=(urlsplit(v).hostname or v) if '://' in v else v; return v.rstrip('.').casefold()
    def allows_host(self,host):
        host=str(host or '').rstrip('.').casefold()
        if not host or any(fnmatch.fnmatch(host,p.casefold()) for p in self.exclusions): return False
        root=self.root_host()
        if host==root: return True
        try: addr=ip_address(host)
        except Exception: addr=None
        if addr is not None:
            for cidr in self.allowed_cidrs:
                try:
                    if addr in ip_network(cidr,strict=False): return True
                except Exception: pass
            return False
        return self.allow_subdomains and host.endswith('.'+root)
    def allows_url(self,url):
        p=urlsplit(url); return p.scheme in {'http','https'} and self.allows_host(p.hostname or '')
    def to_dict(self): return {'root':self.root,'allow_subdomains':self.allow_subdomains,'allowed_cidrs':self.allowed_cidrs,'exclusions':self.exclusions}
def build_scope(root,allow_subdomains=True,allowed_cidrs=None,exclusions=None): return ScopePolicy(root,allow_subdomains,list(allowed_cidrs or []),list(exclusions or []))
