from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "forwarder_config",
    ROOT / "scripts" / "forwarder_config.py",
)
assert SPEC and SPEC.loader
forwarder_config = importlib.util.module_from_spec(SPEC)
sys.modules["forwarder_config"] = forwarder_config
SPEC.loader.exec_module(forwarder_config)


def test_load_valid_config() -> None:
    config = forwarder_config.load_validated_config(ROOT)
    assert sorted(config.enabled_source_ids()) == ["generic-syslog", "windows-ad", "windows-sysmon"]
    assert config.catalog["windows-ad"]["parser"] == "windows-ad-json"


def test_unknown_source_id_rejected(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["sources"]["not-real"] = {"enabled": True, "listen_host": "0.0.0.0", "port": 9999}
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    with pytest.raises(
        ValueError,
        match="unknown source id not-real; supported source IDs: generic-syslog, windows-ad, windows-sysmon",
    ):
        forwarder_config.load_validated_config(tmp_path)


def test_duplicate_enabled_ports_rejected(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["sources"]["windows-ad"]["port"] = doc["sources"]["generic-syslog"]["port"]
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    with pytest.raises(ValueError, match="duplicate enabled port"):
        forwarder_config.load_validated_config(tmp_path)


def test_malicious_listen_host_rejected(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["sources"]["generic-syslog"]["listen_host"] = '0.0.0.0" } output { stdout {}'
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    with pytest.raises(ValueError, match="listen_host"):
        forwarder_config.load_validated_config(tmp_path)


def test_catalog_schema_is_validated(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    catalog = forwarder_config.read_yaml(tmp_path / "config" / "source-catalog.yml")
    del catalog["sources"][0]["parser"]
    forwarder_config.write_yaml(tmp_path / "config" / "source-catalog.yml", catalog)

    with pytest.raises(ValueError, match="parser"):
        forwarder_config.load_validated_config(tmp_path)


def test_catalog_rejects_duplicate_datasets(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    catalog = forwarder_config.read_yaml(tmp_path / "config" / "source-catalog.yml")
    catalog["sources"][1]["dataset"] = catalog["sources"][0]["dataset"]
    forwarder_config.write_yaml(tmp_path / "config" / "source-catalog.yml", catalog)

    with pytest.raises(ValueError, match="duplicate source catalog dataset"):
        forwarder_config.load_validated_config(tmp_path)


def test_queue_size_validation_rejects_oversized_dlq(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["queue"]["max_bytes"] = "512mb"
    doc["queue"]["dlq_max_bytes"] = "1gb"
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    with pytest.raises(ValueError, match="dlq_max_bytes must be less than or equal to max_bytes"):
        forwarder_config.load_validated_config(tmp_path)


def test_disk_headroom_uses_queue_and_dlq_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    config = forwarder_config.load_validated_config(tmp_path)

    class Usage:
        free = 1

    monkeypatch.setattr(forwarder_config.shutil, "disk_usage", lambda _path: Usage())
    with pytest.raises(ValueError, match="insufficient free disk"):
        forwarder_config.check_disk_headroom(tmp_path, config)


def test_required_disk_counts_one_output_queue_plus_one_dlq(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    config = forwarder_config.load_validated_config(tmp_path)
    assert forwarder_config.required_queue_disk_bytes(config) == int(
        (8 * 1024 * 1024 * 1024 + 512 * 1024 * 1024) * 1.2
    )


def test_render_inputs_omits_disabled_source(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    forwarder_config.copy_tree(ROOT / "templates", tmp_path / "templates")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["sources"]["windows-sysmon"]["enabled"] = False
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    config = forwarder_config.load_validated_config(tmp_path)
    rendered = forwarder_config.render_inputs(tmp_path, config)
    assert "windows-ad" in rendered
    assert "generic-syslog" in rendered
    assert "windows-sysmon" not in rendered


def test_render_logstash_uses_queue_settings(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    forwarder_config.copy_tree(ROOT / "templates", tmp_path / "templates")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["queue"]["max_bytes"] = "16gb"
    doc["queue"]["dlq_max_bytes"] = "1gb"
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    config = forwarder_config.load_validated_config(tmp_path)
    rendered = forwarder_config.render_logstash(tmp_path, config)
    assert "queue.max_bytes: 16gb" in rendered
    assert "dead_letter_queue.max_bytes: 1gb" in rendered


def test_render_inputs_uses_canonical_metadata_and_observer_name(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    forwarder_config.copy_tree(ROOT / "templates", tmp_path / "templates")

    config = forwarder_config.load_validated_config(tmp_path)
    rendered = forwarder_config.render_inputs(tmp_path, config)
    assert '"[@metadata][forwarder][source_id]" => "windows-ad"' in rendered
    assert '"[@metadata][forwarder][parser]" => "windows-ad-json"' in rendered
    assert '"[siem][source_id]" => "windows-ad"' not in rendered
    assert '"[@metadata][forwarder][observer_name]" => "customer-forwarder-01"' in rendered
    assert "ssl_enabled => true" in rendered
    assert 'user => "${WINDOWS_HTTP_USERNAME}"' in rendered
    assert 'password => "${WINDOWS_HTTP_PASSWORD}"' in rendered
    assert 'ssl_client_authentication => "required"' in rendered
