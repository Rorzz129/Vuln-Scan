from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(slots=True)
class TemplateRequest:
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    timeout: float = 5.0

@dataclass(slots=True)
class TemplateMatcher:
    type: str
    part: str = "body"
    condition: str = "contains"
    value: Any = None
    values: list[Any] = field(default_factory=list)
    negate: bool = False
    case_sensitive: bool = False

@dataclass(slots=True)
class TemplateExtractor:
    name: str
    type: str = "regex"
    part: str = "body"
    pattern: str = ""
    group: int = 1
    required: bool = False

@dataclass(slots=True)
class TemplateValidation:
    reject_soft404: bool = False
    max_soft404_similarity: float = 0.90
    content_types: list[str] = field(default_factory=list)
    require_same_origin: bool = True
    verification: str = "OBSERVED"

@dataclass(slots=True)
class Template:
    id: str
    name: str
    severity: str
    category: str
    description: str
    recommendation: str
    tags: list[str]
    requests: list[TemplateRequest]
    matchers: list[TemplateMatcher]
    extractors: list[TemplateExtractor] = field(default_factory=list)
    matcher_condition: str = "AND"
    confidence: str = "HIGH"
    enabled: bool = True
    min_profile: int = 1
    requires_technologies: list[str] = field(default_factory=list)
    excludes_technologies: list[str] = field(default_factory=list)
    requires_ports: list[int] = field(default_factory=list)
    requires_http_status: list[int] = field(default_factory=list)
    allow_degraded: bool = False
    stop_at_first_match: bool = True
    validation: TemplateValidation = field(default_factory=TemplateValidation)
    concept: str = ""
    requires_tags: list[str] = field(default_factory=list)
    excludes_tags: list[str] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    extractors: list[dict] = field(default_factory=list)
    max_matches: int = 20
