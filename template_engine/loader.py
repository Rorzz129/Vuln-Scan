from __future__ import annotations
from pathlib import Path
from typing import Any
import json

from template_engine.models import (
    Template,
    TemplateRequest,
    TemplateMatcher,
    TemplateExtractor,
    TemplateValidation,
)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

def _read_document(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()

    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                "YAML templates require PyYAML: pip install pyyaml"
            ) from exc
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        raise ValueError(f"unsupported template format: {path.suffix}")

    if not isinstance(data, dict):
        raise ValueError("template root must be an object/mapping")

    return data

def _parse_request(data: dict[str, Any]) -> TemplateRequest:
    method = str(data.get("method") or "GET").upper()

    if method not in SAFE_METHODS:
        raise ValueError(
            f"unsafe method {method}; only GET, HEAD and OPTIONS are allowed"
        )

    return TemplateRequest(
        method=method,
        path=str(data.get("path") or "/"),
        headers={
            str(k): str(v)
            for k, v in (data.get("headers") or {}).items()
        },
        follow_redirects=bool(data.get("follow_redirects", True)),
        timeout=max(1.0, min(15.0, float(data.get("timeout", 5.0)))),
    )

def _parse_matcher(item: dict[str, Any]) -> TemplateMatcher:
    return TemplateMatcher(
        type=str(item.get("type") or "word").lower(),
        part=str(item.get("part") or "body").lower(),
        condition=str(item.get("condition") or "contains").lower(),
        value=item.get("value"),
        values=list(item.get("values") or []),
        negate=bool(item.get("negate", False)),
        case_sensitive=bool(item.get("case_sensitive", False)),
    )

def _parse_extractor(item: dict[str, Any]) -> TemplateExtractor:
    return TemplateExtractor(
        name=str(item.get("name") or "value"),
        type=str(item.get("type") or "regex").lower(),
        part=str(item.get("part") or "body").lower(),
        pattern=str(item.get("pattern") or ""),
        group=max(0, int(item.get("group", 1))),
        required=bool(item.get("required", False)),
    )

def _parse_validation(
    data: dict[str, Any],
) -> TemplateValidation:
    value = data.get(
        "validation"
    ) or {}

    return TemplateValidation(
        reject_soft404=bool(
            value.get(
                "reject_soft404",
                False,
            )
        ),
        max_soft404_similarity=max(
            0.5,
            min(
                1.0,
                float(
                    value.get(
                        "max_soft404_similarity",
                        0.90,
                    )
                ),
            ),
        ),
        content_types=[
            str(item)
            for item
            in (
                value.get(
                    "content_types"
                )
                or []
            )
        ],
        require_same_origin=bool(
            value.get(
                "require_same_origin",
                True,
            )
        ),
        verification=str(
            value.get(
                "verification",
                "OBSERVED",
            )
        ).upper(),
    )

def _to_template(data: dict[str, Any]) -> Template:
    request_data = data.get("request") or {}
    requests_data = data.get("requests")

    if requests_data is None:
        requests_data = [request_data]

    if not isinstance(requests_data, list) or not requests_data:
        raise ValueError("template must define request or requests")

    requests = [
        _parse_request(item)
        for item in requests_data
        if isinstance(item, dict)
    ]

    if not requests:
        raise ValueError("template has no valid requests")

    matchers = [
        _parse_matcher(item)
        for item in (data.get("matchers") or [])
        if isinstance(item, dict)
    ]

    extractors = [
        _parse_extractor(item)
        for item in (data.get("extractors") or [])
        if isinstance(item, dict)
    ]

    preconditions = data.get("preconditions") or {}

    return Template(
        id=str(data.get("id") or "").strip(),
        name=str(data.get("name") or "").strip(),
        severity=str(data.get("severity") or "INFO").upper(),
        category=str(data.get("category") or "Template").strip(),
        description=str(data.get("description") or "").strip(),
        recommendation=str(data.get("recommendation") or "").strip(),
        tags=[str(tag) for tag in (data.get("tags") or [])],
        requests=requests,
        matchers=matchers,
        extractors=extractors,
        matcher_condition=str(data.get("matcher_condition") or "AND").upper(),
        confidence=str(data.get("confidence") or "HIGH").upper(),
        enabled=bool(data.get("enabled", True)),
        min_profile=max(1, min(3, int(data.get("min_profile", 1)))),
        requires_technologies=[
            str(v)
            for v in (preconditions.get("technologies") or [])
        ],
        excludes_technologies=[
            str(v)
            for v in (preconditions.get("exclude_technologies") or [])
        ],
        requires_ports=[
            int(v)
            for v in (preconditions.get("ports") or [])
        ],
        requires_http_status=[
            int(v)
            for v in (preconditions.get("http_status") or [])
        ],
        allow_degraded=bool(data.get("allow_degraded", False)),
        stop_at_first_match=bool(data.get("stop_at_first_match", True)),
        validation=_parse_validation(data),
        concept=str(
            data.get("concept")
            or ""
        ).strip(),
    )

def load_templates(
    directory: str | Path,
) -> tuple[list[Template], list[dict[str, str]]]:
    directory = Path(directory)
    templates: list[Template] = []
    errors: list[dict[str, str]] = []
    ids: set[str] = set()

    if not directory.exists():
        return templates, errors

    for path in sorted(directory.rglob("*")):
        if (
            not path.is_file()
            or path.suffix.lower() not in {".json", ".yaml", ".yml"}
        ):
            continue

        try:
            template = _to_template(_read_document(path))

            if not template.id or not template.name:
                raise ValueError("template id and name are required")

            if template.id in ids:
                raise ValueError(f"duplicate template id: {template.id}")

            ids.add(template.id)
            templates.append(template)

        except Exception as exc:
            errors.append({
                "file": str(path),
                "error": f"{type(exc).__name__}: {exc}",
            })

    return templates, errors
