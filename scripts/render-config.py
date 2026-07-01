#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from forwarder_config import load_validated_config, write_rendered_inputs, write_rendered_logstash


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    config = load_validated_config(root)
    logstash_path = write_rendered_logstash(root, config)
    inputs_path = write_rendered_inputs(root, config)
    print(f"rendered {logstash_path.relative_to(root)}")
    print(f"rendered {inputs_path.relative_to(root)}")


if __name__ == "__main__":
    main()
