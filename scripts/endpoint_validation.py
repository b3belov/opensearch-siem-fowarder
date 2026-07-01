from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


VALID_ENDPOINT_CASES = [
    "https://siem.example.com:5044/",
    "https://10.2.9.22:5044/ingest",
]
INVALID_ENDPOINT_CASES = [
    ("http://siem.example.com:5044/", "must use https"),
    ("https://user:pass@siem.example.com:5044/", "must not include username or password"),
    ("https://bad host:5044/", "must not contain whitespace"),
    ("https://siem.example.com:notaport/", "port must be a number"),
]


def validate_https_endpoint(value: str, *, field_name: str = "CENTRAL_INGEST_URL") -> None:
    if any(ch.isspace() for ch in value):
        raise ValueError(f"{field_name} must not contain whitespace")
    parsed = urlparse(value)
    if parsed.scheme != "https":
        raise ValueError(f"{field_name} must use https")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError(f"{field_name} must include a host")
    if parsed.username or parsed.password:
        raise ValueError(f"{field_name} must not include username or password")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} port must be a number between 0 and 65535") from exc
    host = parsed.hostname.rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            not labels
            or any(not label for label in labels)
            or any(len(label) > 63 for label in labels)
            or len(host) > 253
            or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) for label in labels)
        ):
            raise ValueError(f"{field_name} host must be a valid DNS name or IP address")
