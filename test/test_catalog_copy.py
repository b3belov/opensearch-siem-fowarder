from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest
import yaml


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_customer_forwarder_catalog_matches_main_catalog() -> None:
    repo = Path(__file__).resolve().parents[2]
    assert (
        repo / "source-catalog" / "sources.yml"
    ).read_text(encoding="utf-8") == (
        repo / "customer-forwarder" / "config" / "source-catalog.yml"
    ).read_text(encoding="utf-8")


def test_customer_forwarder_catalog_schema_matches_main_catalog_schema() -> None:
    repo = Path(__file__).resolve().parents[2]
    assert (
        repo / "source-catalog" / "sources.schema.json"
    ).read_text(encoding="utf-8") == (
        repo / "customer-forwarder" / "config" / "source-catalog.schema.json"
    ).read_text(encoding="utf-8")


def test_customer_forwarder_endpoint_validator_matches_main_helper() -> None:
    repo = Path(__file__).resolve().parents[2]
    assert (
        repo / "scripts" / "lib" / "endpoint_validation.py"
    ).read_text(encoding="utf-8") == (
        repo / "customer-forwarder" / "scripts" / "endpoint_validation.py"
    ).read_text(encoding="utf-8")


def test_customer_forwarder_catalog_lock_records_synced_files() -> None:
    repo = Path(__file__).resolve().parents[2]
    forwarder = repo / "customer-forwarder"
    lock = yaml.safe_load((forwarder / "config" / "source-catalog.lock").read_text(encoding="utf-8"))
    assert lock["source_repo_commit"]
    assert lock["generated_at"]
    assert lock["supported_source_ids"] == ["generic-syslog", "windows-ad", "windows-sysmon"]
    locked = {entry["target"]: entry["sha256"] for entry in lock["files"]}
    for target in [
        "config/source-catalog.yml",
        "config/source-catalog.schema.json",
        "scripts/endpoint_validation.py",
    ]:
        assert locked[target] == sha256(forwarder / target)


def test_customer_endpoint_validation_uses_shared_vectors() -> None:
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "customer_endpoint_validation",
        repo / "customer-forwarder" / "scripts" / "endpoint_validation.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["customer_endpoint_validation"] = module
    spec.loader.exec_module(module)

    for value in module.VALID_ENDPOINT_CASES:
        module.validate_https_endpoint(value)
    for value, message in module.INVALID_ENDPOINT_CASES:
        with pytest.raises(ValueError, match=message):
            module.validate_https_endpoint(value)
