from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit
import requests
import threading
import time
from requests.adapters import HTTPAdapter

DEFAULT_TIMEOUT=(3.5,5.0)
USER_AGENT="VulnScope/1.3.1 Web Scanner"

SEVERITY_ORDER={"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1,"UNKNOWN":0}
CONFIDENCE_ORDER={"HIGH":3,"MEDIUM":2,"LOW":1,"UNKNOWN":0}

def normalize_url(url:Any)->str:
    value=str(url or "").strip()
    if not value:
        raise ValueError("URL cannot be empty")
    if "://" not in value:
        value=f"https://{value}"
    parsed=urlsplit(value)
    if parsed.scheme.lower() not in {"http","https"} or not parsed.hostname:
        raise ValueError("Invalid HTTP/HTTPS URL")
    host=parsed.hostname.encode("idna").decode("ascii")
    if ":" in host and not host.startswith("["):
        host=f"[{host}]"
    netloc=host
    if parsed.port:
        netloc+=f":{parsed.port}"
    return urlunsplit((parsed.scheme.lower(),netloc,parsed.path or "/",parsed.query,""))

def get_origin(url:str)->str:
    p=urlsplit(normalize_url(url))
    host=p.hostname or ""
    if ":" in host and not host.startswith("["):
        host=f"[{host}]"
    default=443 if p.scheme=="https" else 80
    return f"{p.scheme}://{host}:{p.port}" if p.port and p.port!=default else f"{p.scheme}://{host}"

def create_session()->requests.Session:
    session=requests.Session()
    session.headers.update({
        "User-Agent":USER_AGENT,
        "Accept":"text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Encoding":"gzip, deflate",
    })
    adapter=HTTPAdapter(pool_connections=24,pool_maxsize=24,max_retries=0)
    session.mount("http://",adapter)
    session.mount("https://",adapter)
    return session

def request(session:requests.Session,method:str,url:str,**kwargs:Any)->requests.Response:
    kwargs.setdefault("timeout",DEFAULT_TIMEOUT)
    kwargs.setdefault("allow_redirects",True)
    return session.request(method.upper(),normalize_url(url),**kwargs)


_CACHE_LOCK = threading.RLock()
_HTTP_CACHE: dict[tuple, tuple[float, requests.Response]] = {}
_CACHE_TTL = 180.0
_CACHE_STATS = {"hits": 0, "misses": 0}

def _cache_key(method: str, url: str, headers: dict[str, str] | None = None) -> tuple:
    safe_headers = tuple(sorted((str(k).lower(), str(v)) for k, v in (headers or {}).items()))
    return (method.upper(), normalize_url(url), safe_headers)

def clear_http_cache() -> None:
    with _CACHE_LOCK:
        _HTTP_CACHE.clear()
        _CACHE_STATS["hits"] = 0
        _CACHE_STATS["misses"] = 0

def http_cache_stats() -> dict[str, int]:
    with _CACHE_LOCK:
        return dict(_CACHE_STATS)

def cached_request(session: requests.Session, method: str, url: str, **kwargs: Any) -> requests.Response:
    method = method.upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return request(session, method, url, **kwargs)

    headers = kwargs.get("headers") or {}
    key = _cache_key(method, url, headers)
    now = time.monotonic()

    with _CACHE_LOCK:
        cached = _HTTP_CACHE.get(key)
        if cached and now - cached[0] <= _CACHE_TTL:
            _CACHE_STATS["hits"] += 1
            return cached[1]

    response = request(session, method, url, **kwargs)

    with _CACHE_LOCK:
        _HTTP_CACHE[key] = (now, response)
        _CACHE_STATS["misses"] += 1

    return response

@dataclass(slots=True)
class WebScanContext:
    requested_url:str
    session:requests.Session
    response:requests.Response
    degraded:bool=False
    notes:list[str]=field(default_factory=list)
    @property
    def url(self)->str:
        return self.response.url
    @property
    def origin(self)->str:
        return get_origin(self.response.url)
    @property
    def status_code(self)->int:
        return int(self.response.status_code)

def build_context(url:str)->WebScanContext:
    normalized=normalize_url(url)
    session=create_session()
    try:
        response=cached_request(session,"GET",normalized)
    except Exception:
        session.close()
        raise
    degraded=response.status_code>=500
    notes=[]
    if degraded:
        notes.append(
            f"Base page returned HTTP {response.status_code}; active/deep checks were reduced "
            "to avoid false positives and long timeouts."
        )
    return WebScanContext(normalized,session,response,degraded,notes)

def ensure_context(value:str|WebScanContext)->tuple[WebScanContext,bool]:
    if isinstance(value,WebScanContext):
        return value,False
    return build_context(value),True

def make_finding(finding_id:str,title:str,severity:str,category:str,url:str,evidence:str,
                 recommendation:str,confidence:str="HIGH")->dict[str,Any]:
    severity=str(severity or "UNKNOWN").upper()
    confidence=str(confidence or "UNKNOWN").upper()
    if severity not in SEVERITY_ORDER:
        severity="UNKNOWN"
    if confidence not in CONFIDENCE_ORDER:
        confidence="UNKNOWN"
    return {
        "id":str(finding_id),"title":str(title),"severity":severity,"confidence":confidence,
        "category":str(category),"url":str(url),"evidence":str(evidence),
        "recommendation":str(recommendation),
        "verification":"OBSERVED",
        "source":"web-check",
    }

def deduplicate_findings(findings:list[dict[str,Any]])->list[dict[str,Any]]:
    result=[];seen=set()
    for finding in findings:
        if not isinstance(finding,dict):
            continue
        key=(str(finding.get("id","")).upper(),str(finding.get("url","")),str(finding.get("evidence","")))
        if key in seen:
            continue
        seen.add(key);result.append(finding)
    return result

def sort_findings(findings:list[dict[str,Any]])->list[dict[str,Any]]:
    return sorted(findings,key=lambda f:(
        -SEVERITY_ORDER.get(str(f.get("severity","UNKNOWN")).upper(),0),
        -CONFIDENCE_ORDER.get(str(f.get("confidence","UNKNOWN")).upper(),0),
        str(f.get("title","")).casefold()
    ))


def response_text(response: requests.Response, limit: int = 3_000_000) -> str:
    if response is None or limit <= 0:
        return ""
    try:
        text = response.text
    except Exception:
        try:
            text = (response.content or b"").decode(response.encoding or "utf-8", errors="replace")
        except Exception:
            return ""
    return str(text)[:limit]


def resilient_request(
    session: requests.Session,
    method: str,
    url: str,
    *,
    retries: int = 2,
    backoff: float = 0.5,
    retry_statuses: set[int] | None = None,
    **kwargs: Any,
) -> tuple[requests.Response, int]:
    retry_statuses = retry_statuses or {429, 500, 502, 503, 504}
    attempts = 0
    last_response: requests.Response | None = None
    last_error: Exception | None = None

    for attempt in range(max(0, int(retries)) + 1):
        attempts += 1

        try:
            response = cached_request(
                session,
                method,
                url,
                **kwargs,
            )
            last_response = response

            if (
                response.status_code not in retry_statuses
                or attempt >= retries
            ):
                return response, attempts

        except Exception as exc:
            last_error = exc

            if attempt >= retries:
                raise

        if backoff > 0:
            time.sleep(backoff * (2 ** attempt))

    if last_response is not None:
        return last_response, attempts

    if last_error is not None:
        raise last_error

    raise RuntimeError("HTTP request failed without response")
