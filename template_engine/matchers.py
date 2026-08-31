from __future__ import annotations
import re
from typing import Any

from template_engine.models import TemplateMatcher, TemplateExtractor

def part_value(response: Any, part: str) -> Any:
    if part == "status":
        return response.status_code
    if part == "headers":
        return "\n".join(
            f"{k}: {v}"
            for k, v in response.headers.items()
        )
    if part.startswith("header:"):
        name = part.split(":", 1)[1].strip()
        return response.headers.get(name, "")
    if part == "url":
        return response.url
    return response.text

def _match_one(
    response: Any,
    matcher: TemplateMatcher,
) -> bool:
    data = part_value(response, matcher.part)
    values = (
        matcher.values
        if matcher.values
        else [matcher.value]
    )

    if matcher.type == "status":
        expected = {
            int(v)
            for v in values
            if v is not None
        }
        result = int(response.status_code) in expected

    elif matcher.type == "regex":
        text = str(data)
        flags = 0 if matcher.case_sensitive else re.IGNORECASE
        result = any(
            re.search(str(value), text, flags) is not None
            for value in values
            if value is not None
        )

    elif matcher.type == "word":
        text = str(data)
        test_text = (
            text
            if matcher.case_sensitive
            else text.lower()
        )
        normalized = [
            (
                str(value)
                if matcher.case_sensitive
                else str(value).lower()
            )
            for value in values
            if value is not None
        ]

        if matcher.condition == "equals":
            result = any(
                test_text == value
                for value in normalized
            )
        elif matcher.condition == "starts_with":
            result = any(
                test_text.startswith(value)
                for value in normalized
            )
        elif matcher.condition == "ends_with":
            result = any(
                test_text.endswith(value)
                for value in normalized
            )
        elif matcher.condition == "contains_all":
            result = all(
                value in test_text
                for value in normalized
            )
        elif matcher.condition == "not_contains":
            result = all(
                value not in test_text
                for value in normalized
            )
        else:
            result = any(
                value in test_text
                for value in normalized
            )

    else:
        result = False

    return not result if matcher.negate else result

def match_response(
    response: Any,
    matchers: list[TemplateMatcher],
    condition: str = "AND",
) -> tuple[bool, list[str]]:
    if not matchers:
        return False, []

    results = []
    evidence = []

    for matcher in matchers:
        matched = _match_one(
            response,
            matcher,
        )
        results.append(matched)

        if matched:
            value = (
                matcher.values
                if matcher.values
                else matcher.value
            )
            evidence.append(
                f"{matcher.type}:{matcher.part}:"
                f"{matcher.condition} -> {value}"
            )

    overall = (
        any(results)
        if condition.upper() == "OR"
        else all(results)
    )

    return overall, evidence

def extract_values(
    response: Any,
    extractors: list[TemplateExtractor],
) -> tuple[dict[str, list[str]], list[str]]:
    extracted: dict[str, list[str]] = {}
    missing_required: list[str] = []

    for extractor in extractors:
        values: list[str] = []
        data = str(
            part_value(
                response,
                extractor.part,
            )
        )

        if extractor.type == "regex":
            if extractor.pattern:
                for match in re.finditer(
                    extractor.pattern,
                    data,
                    re.IGNORECASE,
                ):
                    try:
                        value = match.group(extractor.group)
                    except IndexError:
                        value = match.group(0)

                    if value not in values:
                        values.append(value)

        elif extractor.type == "header":
            value = str(
                response.headers.get(
                    extractor.pattern,
                    "",
                )
            ).strip()

            if value:
                values.append(value)

        extracted[extractor.name] = values

        if extractor.required and not values:
            missing_required.append(
                extractor.name
            )

    return extracted, missing_required
