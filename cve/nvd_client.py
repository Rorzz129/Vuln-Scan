from __future__ import annotations

import os
import random
import threading
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

DEFAULT_TIMEOUT = 20
DEFAULT_RETRIES = 5
USER_AGENT = "VulnScope/2.2 CVE Scanner"

_lock = threading.Lock()
_last_request_time = 0.0


def get_api_key() -> str | None:
    value = os.getenv("NVD_API_KEY", "").strip()

    if not value or value.upper() in {
        "YOUR_NVD_API_KEY",
        "NONE",
        "NULL",
    }:
        return None

    return value


def _min_delay() -> float:
    return 0.7 if get_api_key() else 6.0


def _throttle() -> None:
    global _last_request_time

    with _lock:
        elapsed = time.monotonic() - _last_request_time
        wait = _min_delay() - elapsed

        if wait > 0:
            time.sleep(wait)

        _last_request_time = time.monotonic()


def create_session() -> requests.Session:
    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })

    api_key = get_api_key()

    if api_key:
        session.headers["apiKey"] = api_key

    adapter = HTTPAdapter(
        pool_connections=4,
        pool_maxsize=4,
        max_retries=0,
    )

    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return session


def _retry_delay(
    attempt: int,
    response: requests.Response | None = None,
) -> float:
    if response is not None:
        retry_after = response.headers.get("Retry-After")

        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass

    return min(30.0, 2.0 ** attempt) + random.uniform(0.0, 0.5)


def nvd_get(
    url: str,
    params: dict[str, Any] | list[tuple[str, Any]] | None = None,
    *,
    retries: int = DEFAULT_RETRIES,
    timeout: int = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    own_session = session is None
    session = session or create_session()
    last_error: Exception | None = None

    try:
        for attempt in range(max(1, retries)):
            _throttle()
            response: requests.Response | None = None

            try:
                response = session.get(
                    url,
                    params=params or {},
                    timeout=timeout,
                )

                if response.status_code == 429 or 500 <= response.status_code < 600:
                    if attempt + 1 < retries:
                        time.sleep(_retry_delay(attempt, response))
                        continue

                response.raise_for_status()

                data = response.json()

                if not isinstance(data, dict):
                    raise ValueError("NVD response is not a JSON object")

                return data

            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError,
                ValueError,
            ) as error:
                last_error = error

                if attempt + 1 >= retries:
                    break

                time.sleep(_retry_delay(attempt, response))

        raise RuntimeError(
            f"NVD request failed after {max(1, retries)} attempt(s): {last_error}"
        )

    finally:
        if own_session:
            session.close()


def nvd_paginated_get(
    url: str,
    params: dict[str, Any] | list[tuple[str, Any]] | None = None,
    *,
    result_key: str,
    limit: int | None = None,
    results_per_page: int = 200,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    base_params = list(params.items()) if isinstance(params, dict) else list(params or [])
    results: list[dict[str, Any]] = []
    start_index = 0
    session = create_session()

    try:
        while True:
            if limit is not None and len(results) >= limit:
                break

            page_size = results_per_page

            if limit is not None:
                page_size = min(page_size, limit - len(results))

            if page_size <= 0:
                break

            page_params = [
                *base_params,
                ("startIndex", start_index),
                ("resultsPerPage", page_size),
            ]

            data = nvd_get(
                url,
                page_params,
                timeout=timeout,
                session=session,
            )

            page = data.get(result_key, [])

            if not isinstance(page, list) or not page:
                break

            results.extend(
                item
                for item in page
                if isinstance(item, dict)
            )

            returned = len(page)
            total = data.get("totalResults")

            if returned <= 0:
                break

            start_index += returned

            if isinstance(total, int) and start_index >= total:
                break

    finally:
        session.close()

    return results[:limit] if limit is not None else results
