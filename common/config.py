import os
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Iterable
from urllib.parse import urlparse


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def csv_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Credential:
    username: str
    password: str

    @property
    def redacted(self) -> dict[str, str]:
        return {"username": self.username, "password": "***"}


def parse_credentials(raw: str | None) -> list[Credential]:
    credentials: list[Credential] = []
    for item in csv_list(raw):
        if ":" not in item:
            continue
        username, password = item.split(":", 1)
        username = username.strip()
        password = password.strip()
        if username and password:
            credentials.append(Credential(username=username, password=password))
    return credentials


def safe_target_urls(raw_targets: str | None, raw_allowed_hosts: str | None) -> list[str]:
    """Return validated Docker-only HTTP targets."""

    targets = csv_list(raw_targets)
    allowed_hosts = set(csv_list(raw_allowed_hosts))
    if not targets:
        return []
    if not allowed_hosts:
        raise ValueError("ALLOWED_TARGET_HOSTS must be set for scanner safety")

    validated: list[str] = []
    for target in targets:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        if parsed.scheme != "http":
            raise ValueError(f"Only http:// Docker service URLs are allowed: {target}")
        if parsed.username or parsed.password:
            raise ValueError(f"Target URL must not include credentials: {target}")
        try:
            ip_address(host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False
        if is_ip_literal:
            raise ValueError(f"Target host must be a Docker service name, not an IP address: {target}")
        if "." in host or host in {"localhost", "0.0.0.0"}:
            raise ValueError(f"Target host must be a single Docker service name: {target}")
        if host not in allowed_hosts:
            raise ValueError(f"Target host {host!r} is not in ALLOWED_TARGET_HOSTS")
        if parsed.path not in {"", "/"}:
            raise ValueError(f"Target URL must point to the service root: {target}")
        if parsed.query or parsed.fragment:
            raise ValueError(f"Target URL must not include query or fragment: {target}")
        validated.append(target.rstrip("/"))
    return validated


def safe_internal_service_url(raw_url: str | None, raw_allowed_hosts: str | None, 
allowed_paths: Iterable[str]) -> str:
    """Validate a single internal HTTP service URL."""

    if not raw_url:
        raise ValueError("internal service URL must be set")
    allowed_hosts = set(csv_list(raw_allowed_hosts))
    if not allowed_hosts:
        raise ValueError("allowed internal service hosts must be set")

    parsed = urlparse(raw_url)
    host = parsed.hostname or ""
    if parsed.scheme != "http":
        raise ValueError(f"Only http:// Docker service URLs are allowed: {raw_url}")
    if parsed.username or parsed.password:
        raise ValueError(f"Internal service URL must not include credentials: {raw_url}")
    try:
        ip_address(host)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False
    if is_ip_literal:
        raise ValueError(f"Internal service host must be a Docker service name, not an IP address: {raw_url}")
    if "." in host or host in {"localhost", "0.0.0.0"}:
        raise ValueError(f"Internal service host must be a single Docker service name: {raw_url}")
    if host not in allowed_hosts:
        raise ValueError(f"Internal service host {host!r} is not in the allowlist")
    if parsed.path not in set(allowed_paths):
        raise ValueError(f"Internal service URL path is not allowed: {raw_url}")
    if parsed.query or parsed.fragment:
        raise ValueError(f"Internal service URL must not include query or fragment: {raw_url}")
    return raw_url.rstrip("/")


def first_credential(credentials: Iterable[Credential]) -> Credential | None:
    for credential in credentials:
        return credential
    return None
