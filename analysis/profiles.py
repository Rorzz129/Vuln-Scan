from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    web_checks: tuple[str, ...]
    template_workers: int
    template_level: int
    description: str
    http_retries: int
    retry_backoff: float
    template_request_budget: int

PROFILES = {
    "FAST": ScanProfile(
        name="FAST",
        web_checks=("security_headers", "cookies", "transport", "discovery"),
        template_workers=3,
        template_level=1,
        description="Low-request reconnaissance and passive HTTP checks.",
        http_retries=1,
        retry_backoff=0.35,
        template_request_budget=12,
    ),
    "NORMAL": ScanProfile(
        name="NORMAL",
        web_checks=("security_headers", "cookies", "cors", "http_methods", "sensitive_paths", "transport", "discovery", "page_security"),
        template_workers=6,
        template_level=2,
        description="Balanced vulnerability scan with common safe checks.",
        http_retries=2,
        retry_backoff=0.5,
        template_request_budget=30,
    ),
    "DEEP": ScanProfile(
        name="DEEP",
        web_checks=("security_headers", "cookies", "cors", "http_methods", "sensitive_paths", "transport", "discovery", "page_security", "js_intelligence"),
        template_workers=10,
        template_level=3,
        description="Extended safe checks and all template levels.",
        http_retries=3,
        retry_backoff=0.65,
        template_request_budget=80,
    ),
}

def get_profile(value: str | None) -> ScanProfile:
    name = str(value or "NORMAL").strip().upper()
    return PROFILES.get(name, PROFILES["NORMAL"])
