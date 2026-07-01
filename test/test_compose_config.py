from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "forwarder_config",
    ROOT / "scripts" / "forwarder_config.py",
)
assert SPEC and SPEC.loader
forwarder_config = importlib.util.module_from_spec(SPEC)
sys.modules["forwarder_config"] = forwarder_config
SPEC.loader.exec_module(forwarder_config)


def test_compose_ports_match_enabled_forwarder_sources() -> None:
    config = forwarder_config.load_validated_config(ROOT)
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    ports = set(compose["services"]["customer-forwarder"]["ports"])
    for source in config.enabled_sources():
        assert f"{source['port']}:{source['port']}/tcp" in ports
        if source["input"] == "syslog":
            assert f"{source['port']}:{source['port']}/udp" in ports
    assert "127.0.0.1:9600:9600/tcp" in ports


def test_pipelines_have_explicit_worker_and_batch_settings() -> None:
    pipelines = yaml.safe_load((ROOT / "config" / "pipelines.yml").read_text(encoding="utf-8"))
    for pipeline in pipelines:
        assert isinstance(pipeline["path.config"], str)
        assert "pipeline.workers" in pipeline
        assert "pipeline.batch.size" in pipeline
        assert "pipeline.batch.delay" in pipeline
    by_id = {pipeline["pipeline.id"]: pipeline for pipeline in pipelines}
    assert by_id["inputs"]["queue.type"] == "memory"
    assert by_id["parse-and-normalize"]["queue.type"] == "memory"
    assert by_id["output-ingest-edge"]["queue.type"] == "persisted"


def test_parse_pipeline_has_receiver() -> None:
    receiver = (ROOT / "pipeline" / "10-parse-input.conf").read_text(encoding="utf-8")
    assert 'address => "parse-and-normalize"' in receiver
    assert 'remove_field => [' in receiver
    assert '"[siem][source_id]" => "%{[@metadata][forwarder][source_id]}"' in receiver
    assert '"[siem][parser]" => "%{[@metadata][forwarder][parser]}"' in receiver


def test_every_catalog_parser_has_pipeline_branch() -> None:
    config = forwarder_config.load_validated_config(ROOT)
    parser_files = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "pipeline").glob("*parse-*.conf"))
        if path.name != "10-parse-input.conf"
    )
    for entry in config.catalog.values():
        assert f'[@metadata][forwarder][parser] == "{entry["parser"]}"' in parser_files


def test_output_pipeline_uses_http_output_ca_option() -> None:
    output = (ROOT / "pipeline" / "90-output-ingest-edge.conf").read_text(encoding="utf-8")
    assert 'ssl_verification_mode => "full"' in output
    assert 'cacert => "${CENTRAL_CA_CERT}"' in output
    assert "ssl_certificate_authorities" not in output


def test_compose_has_runtime_guardrails() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["customer-forwarder"]
    assert "@sha256:" in service["image"]
    assert "<resolved-image-digest>" not in service["image"]
    assert service["mem_limit"] == "${FORWARDER_MEM_LIMIT:-1g}"
    assert service["logging"]["options"]["max-size"] == "10m"
    assert service["logging"]["options"]["max-file"] == "5"
    assert service["environment"]["LS_JAVA_OPTS"] == "${LS_JAVA_OPTS:--Xms512m -Xmx512m}"
    assert service["environment"]["WINDOWS_HTTP_USERNAME"] == "${WINDOWS_HTTP_USERNAME}"
    assert service["environment"]["WINDOWS_HTTP_PASSWORD"] == "${WINDOWS_HTTP_PASSWORD}"
    assert "./http-certs:/usr/share/logstash/config/http:ro" in service["volumes"]
