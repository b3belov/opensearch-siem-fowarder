from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("load_smoke", ROOT / "scripts" / "load-smoke.py")
assert SPEC and SPEC.loader
load_smoke = importlib.util.module_from_spec(SPEC)
sys.modules["load_smoke"] = load_smoke
SPEC.loader.exec_module(load_smoke)


def stats(output_out: int, queued: int) -> dict:
    return {
        "pipelines": {
            "output-ingest-edge": {
                "events": {"out": output_out},
                "queue": {"events_count": queued},
            }
        }
    }


def test_stats_progress_requires_expected_output_delta() -> None:
    with pytest.raises(SystemExit, match="expected at least 100"):
        load_smoke.validate_stats_progress(
            stats(10, 0),
            stats(50, 0),
            expected_output_delta=100,
            max_queue_growth=0,
        )


def test_stats_progress_rejects_queue_growth_by_default() -> None:
    with pytest.raises(SystemExit, match="queued event count grew"):
        load_smoke.validate_stats_progress(
            stats(10, 0),
            stats(110, 1),
            expected_output_delta=100,
            max_queue_growth=0,
        )


def test_stats_progress_accepts_output_delta_without_queue_growth() -> None:
    load_smoke.validate_stats_progress(
        stats(10, 0),
        stats(110, 0),
        expected_output_delta=100,
        max_queue_growth=0,
    )
