#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import ssl
import time
from typing import Optional
import urllib.request
from pathlib import Path


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def pipeline_event_count(stats: dict, pipeline_id: str, field: str) -> int:
    return int(stats.get("pipelines", {}).get(pipeline_id, {}).get("events", {}).get(field, 0))


def queued_event_count(stats: dict) -> int:
    total = 0
    for pipeline in stats.get("pipelines", {}).values():
        queue = pipeline.get("queue", {})
        total += int(queue.get("events_count", 0) or 0)
    return total


def ssl_context(args: argparse.Namespace) -> Optional[ssl.SSLContext]:
    if not args.url.startswith("https://"):
        return None
    if not args.ca_cert or not args.client_cert or not args.client_key:
        raise SystemExit("HTTPS smoke requires --ca-cert, --client-cert, and --client-key")
    context = ssl.create_default_context(cafile=args.ca_cert)
    context.load_cert_chain(certfile=args.client_cert, keyfile=args.client_key)
    return context


def validate_stats_progress(
    before: dict,
    after: dict,
    *,
    expected_output_delta: int,
    max_queue_growth: int,
) -> None:
    output_before = pipeline_event_count(before, "output-ingest-edge", "out")
    output_after = pipeline_event_count(after, "output-ingest-edge", "out")
    if output_after - output_before < expected_output_delta:
        raise SystemExit(
            "output-ingest-edge events.out advanced "
            f"{output_after - output_before}, expected at least {expected_output_delta}"
        )
    queued_before = queued_event_count(before)
    queued_after = queued_event_count(after)
    if queued_after - queued_before > max_queue_growth:
        raise SystemExit(
            f"Logstash queued event count grew by {queued_after - queued_before}, "
            f"allowed {max_queue_growth}"
        )


def post_once(url: str, body: bytes, context: Optional[ssl.SSLContext], auth_header: str) -> None:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Authorization": auth_header},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5, context=context) as response:
        if response.status >= 300:
            raise SystemExit(f"unexpected HTTP status {response.status}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="https://localhost:8082/")
    parser.add_argument("--monitor-url", default="http://127.0.0.1:9600/_node/stats/pipelines")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--fixture", default="test/fixtures/windows-sysmon.json")
    parser.add_argument("--min-events-per-second", type=float, default=25.0)
    parser.add_argument("--username", default="windows-forwarder")
    parser.add_argument("--password", required=True)
    parser.add_argument("--ca-cert")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--min-output-events", type=int)
    parser.add_argument("--max-queue-growth", type=int, default=0)
    parser.add_argument("--skip-monitor", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    payload = json.loads((root / args.fixture).read_text(encoding="utf-8"))
    body = json.dumps(payload).encode("utf-8")
    context = ssl_context(args)
    auth = base64.b64encode(f"{args.username}:{args.password}".encode("utf-8")).decode("ascii")
    auth_header = f"Basic {auth}"
    before = None if args.skip_monitor else fetch_json(args.monitor_url)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        list(executor.map(lambda _index: post_once(args.url, body, context, auth_header), range(args.count)))
    elapsed = time.perf_counter() - started
    rate = args.count / elapsed
    print(f"sent {args.count} events in {elapsed:.2f}s ({rate:.1f} events/s)")
    if rate < args.min_events_per_second:
        raise SystemExit(
            f"event rate {rate:.1f}/s below target {args.min_events_per_second:.1f}/s"
        )
    if before is not None:
        time.sleep(2)
        after = fetch_json(args.monitor_url)
        validate_stats_progress(
            before,
            after,
            expected_output_delta=args.min_output_events or args.count,
            max_queue_growth=args.max_queue_growth,
        )


if __name__ == "__main__":
    main()
