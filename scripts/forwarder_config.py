from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader
from jsonschema import Draft202012Validator


SAFE_LOGSTASH_STRING = re.compile(r"^[A-Za-z0-9._:-]+$")
SIZE_RE = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>mb|gb)$")
MIN_QUEUE_BYTES = 64 * 1024 * 1024
MAX_QUEUE_BYTES = 1024 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class ForwarderConfig:
    root: Path
    raw: dict[str, Any]
    catalog: dict[str, dict[str, Any]]

    def enabled_source_ids(self) -> list[str]:
        return [
            source_id
            for source_id, settings in self.raw["sources"].items()
            if settings.get("enabled") is True
        ]

    def enabled_sources(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for source_id in self.enabled_source_ids():
            settings = self.raw["sources"][source_id]
            catalog_entry = self.catalog[source_id]
            result.append({
                "id": source_id,
                "dataset": catalog_entry["dataset"],
                "parser": catalog_entry["parser"],
                "input": catalog_entry["input"],
                "forwarder_name": self.raw["forwarder_name"],
                "listen_host": settings["listen_host"],
                "port": settings["port"],
            })
        return result

    def queue_settings(self) -> dict[str, str]:
        return {
            "max_bytes": self.raw["queue"]["max_bytes"],
            "dlq_max_bytes": self.raw["queue"]["dlq_max_bytes"],
        }

    def http_collector_settings(self) -> dict[str, Any]:
        settings = dict(self.raw["http_collector"])
        basic_auth = dict(settings["basic_auth"])
        basic_auth["username_ref"] = "${" + basic_auth["username_env"] + "}"
        basic_auth["password_ref"] = "${" + basic_auth["password_env"] + "}"
        settings["basic_auth"] = basic_auth
        return settings


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected YAML mapping")
    return value


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_yaml(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(value, handle, sort_keys=False)


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def validate_schema(document: dict[str, Any], schema: dict[str, Any], path: Path) -> None:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        rendered = "; ".join(f"{'/'.join(map(str, error.path))}: {error.message}" for error in errors)
        raise ValueError(f"{path}: {rendered}")


def parse_size_bytes(value: str) -> int:
    match = SIZE_RE.fullmatch(value)
    if not match:
        raise ValueError(f"invalid size {value!r}; expected values like 512mb or 8gb")
    amount = int(match.group("amount"))
    multiplier = 1024 * 1024 if match.group("unit") == "mb" else 1024 * 1024 * 1024
    return amount * multiplier


def load_catalog(root: Path) -> dict[str, dict[str, Any]]:
    catalog_path = root / "config" / "source-catalog.yml"
    schema_path = root / "config" / "source-catalog.schema.json"
    doc = read_yaml(catalog_path)
    schema = read_json(schema_path)
    validate_schema(doc, schema, catalog_path)
    entries = doc.get("sources")
    if not isinstance(entries, list):
        raise ValueError(f"{catalog_path}: sources must be a list")
    result: dict[str, dict[str, Any]] = {}
    seen_datasets: set[str] = set()
    for entry in entries:
        source_id = entry["id"]
        dataset = entry["dataset"]
        if source_id in result:
            raise ValueError(f"{catalog_path}: duplicate source id {source_id}")
        if dataset in seen_datasets:
            raise ValueError(f"{catalog_path}: duplicate source catalog dataset {dataset}")
        seen_datasets.add(dataset)
        result[source_id] = entry
    return result


def load_validated_config(root: Path) -> ForwarderConfig:
    schema_path = root / "config" / "forwarder.schema.json"
    config_path = root / "config" / "forwarder.yml"
    schema = read_json(schema_path)
    config = read_yaml(config_path)
    validate_schema(config, schema, config_path)
    catalog = load_catalog(root)

    queue_max = parse_size_bytes(config["queue"]["max_bytes"])
    dlq_max = parse_size_bytes(config["queue"]["dlq_max_bytes"])
    if queue_max < MIN_QUEUE_BYTES:
        raise ValueError(f"{config_path}: queue.max_bytes must be at least 64mb")
    if queue_max > MAX_QUEUE_BYTES:
        raise ValueError(f"{config_path}: queue.max_bytes must be 1024gb or less")
    if dlq_max > queue_max:
        raise ValueError(f"{config_path}: queue.dlq_max_bytes must be less than or equal to max_bytes")

    enabled_ports: dict[int, str] = {}
    for source_id, settings in config["sources"].items():
        if source_id not in catalog:
            supported = ", ".join(sorted(catalog))
            raise ValueError(f"{config_path}: unknown source id {source_id}; supported source IDs: {supported}")
        if not SAFE_LOGSTASH_STRING.fullmatch(settings["listen_host"]):
            raise ValueError(f"{config_path}: listen_host for {source_id} contains unsafe characters")
        if settings["enabled"]:
            port = settings["port"]
            if port in enabled_ports:
                raise ValueError(
                    f"{config_path}: duplicate enabled port {port} for {enabled_ports[port]} and {source_id}"
                )
            enabled_ports[port] = source_id
    return ForwarderConfig(root=root, raw=config, catalog=catalog)


def jinja_env(root: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(root)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )


def render_inputs(root: Path, config: ForwarderConfig) -> str:
    template = jinja_env(root).get_template("templates/pipeline/00-inputs.conf.j2")
    return template.render(
        sources=config.enabled_sources(),
        http_collector=config.http_collector_settings(),
    ).rstrip() + "\n"


def render_logstash(root: Path, config: ForwarderConfig) -> str:
    template = jinja_env(root).get_template("templates/config/logstash.yml.j2")
    return template.render(queue=config.queue_settings()).rstrip() + "\n"


def required_queue_disk_bytes(config: ForwarderConfig) -> int:
    queue_max = parse_size_bytes(config.raw["queue"]["max_bytes"])
    dlq_max = parse_size_bytes(config.raw["queue"]["dlq_max_bytes"])
    return int((queue_max + dlq_max) * 1.2)


def check_disk_headroom(root: Path, config: ForwarderConfig) -> None:
    data_dir = root / "data" / "logstash"
    probe_dir = data_dir if data_dir.exists() else root
    free = shutil.disk_usage(probe_dir).free
    required = required_queue_disk_bytes(config)
    if free < required:
        raise ValueError(
            f"{data_dir}: insufficient free disk for persistent queue and DLQ; "
            f"need at least {required} bytes with 20% headroom, have {free}"
        )


def write_rendered_inputs(root: Path, config: ForwarderConfig) -> Path:
    path = root / "pipeline" / "00-inputs.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_inputs(root, config), encoding="utf-8")
    return path


def write_rendered_logstash(root: Path, config: ForwarderConfig) -> Path:
    path = root / "config" / "logstash.yml"
    path.write_text(render_logstash(root, config), encoding="utf-8")
    return path
