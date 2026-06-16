from typing import Any
import requests

DEFAULT_TIMEOUT_SECONDS = 2.5

def post_json(url: str, payload: dict[str, Any], 
token: str | None = None, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> requests.Response:
    headers = {}
    if token:
        headers["X-Simulation-Token"] = token
    return requests.post(url, json=payload, headers=headers, timeout=timeout)


def get_json(url: str, token: str | None = None, timeout: 
float = DEFAULT_TIMEOUT_SECONDS) -> requests.Response:
    headers = {}
    if token:
        headers["X-Simulation-Token"] = token
    return requests.get(url, headers=headers, timeout=timeout)
