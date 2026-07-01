#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import ssl
from pathlib import Path

from endpoint_validation import validate_https_endpoint


CERT_PREFIX = "/usr/share/logstash/config/certs/"
KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SIZE_RE = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>m|g)$")
HEAP_RE = re.compile(r"^-Xms(?P<xms>[1-9][0-9]*[mg])\s+-Xmx(?P<xmx>[1-9][0-9]*[mg])$")
CENTRAL_CREDENTIAL_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
HTTP_BASIC_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ALLOWED_KEYS = {
    "CENTRAL_INGEST_URL",
    "CUSTOMER_FORWARDER_USERNAME",
    "CUSTOMER_FORWARDER_PASSWORD",
    "CENTRAL_CA_CERT",
    "LS_JAVA_OPTS",
    "FORWARDER_MEM_LIMIT",
    "WINDOWS_HTTP_USERNAME",
    "WINDOWS_HTTP_PASSWORD",
}


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            fail(f"{path}:{lineno}: export syntax is not supported")
        if "=" not in line:
            fail(f"{path}:{lineno}: expected KEY=value")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not KEY_RE.fullmatch(key):
            fail(f"{path}:{lineno}: invalid environment key {key!r}")
        if key not in ALLOWED_KEYS:
            fail(f"{path}:{lineno}: unsupported environment key {key}")
        if value.startswith(("'", '"')):
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                fail(f"{path}:{lineno}: unmatched quote for {key}")
            value = value[1:-1]
        if "$(" in value or "`" in value:
            fail(f"{path}:{lineno}: command substitution is not allowed in {key}")
        values[key] = value
    return values


def require(values: dict[str, str], name: str) -> str:
    value = values.get(name, "")
    if not value:
        fail(f"{name} is required")
    if CONTROL_RE.search(value):
        fail(f"{name} contains control characters")
    return value


def parse_size_bytes(value: str) -> int:
    match = SIZE_RE.fullmatch(value.lower())
    if not match:
        fail(f"invalid size {value!r}; expected values like 512m or 1g")
    amount = int(match.group("amount"))
    multiplier = 1024 * 1024 if match.group("unit") == "m" else 1024 * 1024 * 1024
    return amount * multiplier


def validate_url(value: str) -> None:
    try:
        validate_https_endpoint(value, field_name="CENTRAL_INGEST_URL")
    except ValueError as exc:
        fail(str(exc))


def host_ca_path(root: Path, container_path: str) -> Path:
    if not container_path.startswith(CERT_PREFIX):
        fail(f"CENTRAL_CA_CERT must be under {CERT_PREFIX}")
    relative = container_path.removeprefix(CERT_PREFIX)
    if not relative or ".." in Path(relative).parts:
        fail("CENTRAL_CA_CERT must not contain path traversal")
    certs_root = (root / "certs").resolve()
    ca_path = (certs_root / relative).resolve()
    if not ca_path.is_relative_to(certs_root):
        fail("CENTRAL_CA_CERT must resolve under customer-forwarder/certs")
    return ca_path


def validate_ca(root: Path, container_path: str) -> None:
    ca_path = host_ca_path(root, container_path)
    if not ca_path.is_file():
        fail(f"CENTRAL_CA_CERT host file is missing: {ca_path}")
    try:
        ssl.create_default_context(cafile=str(ca_path))
    except ssl.SSLError as exc:
        fail(f"CENTRAL_CA_CERT must be a parseable CA trust file: {exc}")


def validate_heap(values: dict[str, str]) -> None:
    heap = values.get("LS_JAVA_OPTS", "-Xms512m -Xmx512m")
    match = HEAP_RE.fullmatch(heap)
    if not match:
        fail('LS_JAVA_OPTS must look like "-Xms512m -Xmx512m"')
    xms = parse_size_bytes(match.group("xms"))
    xmx = parse_size_bytes(match.group("xmx"))
    if xms != xmx:
        fail("LS_JAVA_OPTS must use matching Xms and Xmx for predictable sizing")
    mem_limit = parse_size_bytes(values.get("FORWARDER_MEM_LIMIT", "1g"))
    if xmx > int(mem_limit * 0.75):
        fail("LS_JAVA_OPTS Xmx must be no more than 75% of FORWARDER_MEM_LIMIT")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args()

    values = {key: value for key, value in os.environ.items() if key in ALLOWED_KEYS}
    env_file = args.env_file if args.env_file else args.root / ".env"
    if env_file.exists():
        values.update(parse_env_file(env_file))

    url = require(values, "CENTRAL_INGEST_URL")
    username = require(values, "CUSTOMER_FORWARDER_USERNAME")
    password = require(values, "CUSTOMER_FORWARDER_PASSWORD")
    ca_cert = require(values, "CENTRAL_CA_CERT")
    http_username = require(values, "WINDOWS_HTTP_USERNAME")
    http_password = require(values, "WINDOWS_HTTP_PASSWORD")
    validate_url(url)
    if not CENTRAL_CREDENTIAL_ID_RE.fullmatch(username):
        fail("CUSTOMER_FORWARDER_USERNAME must match central credential id pattern ^[a-z][a-z0-9-]{1,40}$")
    if username.startswith("<") or username == "customer-primary":
        fail("CUSTOMER_FORWARDER_USERNAME must be replaced with a real central credential id")
    if password.startswith("<") or password in {"change-me", "changeme"}:
        fail("CUSTOMER_FORWARDER_PASSWORD must be replaced")
    if not HTTP_BASIC_USER_RE.fullmatch(http_username):
        fail("WINDOWS_HTTP_USERNAME contains unsupported characters")
    if http_password.startswith("<") or http_password in {"change-me", "changeme"}:
        fail("WINDOWS_HTTP_PASSWORD must be replaced")
    validate_ca(args.root, ca_cert)
    validate_heap(values)
    print("customer forwarder environment valid")


if __name__ == "__main__":
    main()
