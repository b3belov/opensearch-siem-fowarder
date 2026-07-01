#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
FORWARDER = ROOT / "customer-forwarder"
SYNCED_FILES = [
    (ROOT / "source-catalog" / "sources.yml", FORWARDER / "config" / "source-catalog.yml"),
    (ROOT / "source-catalog" / "sources.schema.json", FORWARDER / "config" / "source-catalog.schema.json"),
    (ROOT / "scripts" / "lib" / "endpoint_validation.py", FORWARDER / "scripts" / "endpoint_validation.py"),
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_commit() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def main() -> None:
    copied = []
    for src, dst in SYNCED_FILES:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        copied.append({
            "source": str(src.relative_to(ROOT)),
            "target": str(dst.relative_to(FORWARDER)),
            "sha256": sha256(dst),
        })
    catalog = yaml.safe_load((FORWARDER / "config" / "source-catalog.yml").read_text(encoding="utf-8"))
    manifest = {
        "source_repo_commit": git_commit(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": copied,
        "supported_source_ids": sorted(item["id"] for item in catalog["sources"]),
    }
    (FORWARDER / "config" / "source-catalog.lock").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    print("synced customer forwarder source catalog")


if __name__ == "__main__":
    main()
