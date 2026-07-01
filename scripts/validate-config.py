#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from forwarder_config import check_disk_headroom, load_validated_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--skip-disk-check", action="store_true")
    args = parser.parse_args()
    root = args.root
    config = load_validated_config(root)
    if not args.skip_disk_check:
        check_disk_headroom(root, config)
    print(f"customer forwarder config valid ({len(config.enabled_source_ids())} enabled sources)")


if __name__ == "__main__":
    main()
