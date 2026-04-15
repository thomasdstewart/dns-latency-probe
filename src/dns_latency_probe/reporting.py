from __future__ import annotations

import json
from pathlib import Path

from dns_latency_probe.analysis import LatencyStats


def write_json_summary(stats: LatencyStats, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(stats.to_dict(), indent=2), encoding="utf-8")


def write_markdown_report(
    stats: LatencyStats,
    output_path: Path,
    pcap_file: str,
    histogram_file: str,
    timeseries_file: str,
) -> None:
    lines = [
        "# DNS Latency Probe Report",
        "",
        "## Artifacts",
        f"- PCAP: `{pcap_file}`",
        f"- Histogram: `{histogram_file}`",
        f"- Time Series: `{timeseries_file}`",
        "",
        "## Summary",
        f"- Total queries sent: {stats.total_queries_sent}",
        f"- Matched responses: {stats.matched_responses}",
        f"- Unmatched queries: {stats.unmatched_queries}",
        f"- Late responses (>1s): {stats.late_responses}",
        f"- Duplicate response candidates dropped: {stats.duplicate_response_candidates}",
        "",
        "## Latency Statistics (seconds)",
        f"- n: {stats.n}",
        f"- min: {stats.min_seconds}",
        f"- max: {stats.max_seconds}",
        f"- mean: {stats.mean_seconds}",
        f"- median: {stats.median_seconds}",
        f"- stddev: {stats.stdev_seconds}",
        f"- p95: {stats.p95_seconds}",
        f"- p99: {stats.p99_seconds}",
        f"- % > 1s: {stats.pct_over_1s}",
        "",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
