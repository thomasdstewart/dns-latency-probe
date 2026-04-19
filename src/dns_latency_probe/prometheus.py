from __future__ import annotations

import os
from pathlib import Path

from dns_latency_probe.analysis import LatencyStats


def _escape_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_float(value: float | None) -> str:
    if value is None:
        return "NaN"
    return f"{value:.12g}"


def write_prometheus_textfile(
    *,
    output_path: Path,
    stats: LatencyStats,
    resolver: str,
    resolver_port: int,
    output_base_name: str,
    run_started_unix: int,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    labels = (
        f'resolver="{_escape_label_value(resolver)}",'
        f'resolver_port="{resolver_port}",'
        f'probe="{_escape_label_value(output_base_name or "default")}"'
    )
    lines = [
        "# HELP dns_probe_run_success Whether the last probe run completed successfully.",
        "# TYPE dns_probe_run_success gauge",
        f"dns_probe_run_success{{{labels}}} 1",
        "# HELP dns_probe_last_run_unixtime Unix time when probe started.",
        "# TYPE dns_probe_last_run_unixtime gauge",
        f"dns_probe_last_run_unixtime{{{labels}}} {run_started_unix}",
        "# HELP dns_probe_queries_sent Total DNS queries sent during the run.",
        "# TYPE dns_probe_queries_sent gauge",
        f"dns_probe_queries_sent{{{labels}}} {stats.total_queries_sent}",
        "# HELP dns_probe_matched_responses Matched DNS responses.",
        "# TYPE dns_probe_matched_responses gauge",
        f"dns_probe_matched_responses{{{labels}}} {stats.matched_responses}",
        "# HELP dns_probe_unmatched_queries DNS queries without a matching response.",
        "# TYPE dns_probe_unmatched_queries gauge",
        f"dns_probe_unmatched_queries{{{labels}}} {stats.unmatched_queries}",
        "# HELP dns_probe_late_responses DNS responses over 1 second latency.",
        "# TYPE dns_probe_late_responses gauge",
        f"dns_probe_late_responses{{{labels}}} {stats.late_responses}",
        "# HELP dns_probe_duplicate_response_candidates Duplicate response candidates dropped.",
        "# TYPE dns_probe_duplicate_response_candidates gauge",
        (
            "dns_probe_duplicate_response_candidates"
            f"{{{labels}}} {stats.duplicate_response_candidates}"
        ),
        "# HELP dns_probe_out_of_order_responses Out-of-order DNS responses.",
        "# TYPE dns_probe_out_of_order_responses gauge",
        f"dns_probe_out_of_order_responses{{{labels}}} {stats.out_of_order_responses}",
        "# HELP dns_probe_stale_responses Stale DNS responses that did not match current queries.",
        "# TYPE dns_probe_stale_responses gauge",
        f"dns_probe_stale_responses{{{labels}}} {stats.stale_responses}",
        "# HELP dns_probe_latency_min_seconds Minimum matched DNS latency in seconds.",
        "# TYPE dns_probe_latency_min_seconds gauge",
        f"dns_probe_latency_min_seconds{{{labels}}} {_format_float(stats.min_seconds)}",
        "# HELP dns_probe_latency_max_seconds Maximum matched DNS latency in seconds.",
        "# TYPE dns_probe_latency_max_seconds gauge",
        f"dns_probe_latency_max_seconds{{{labels}}} {_format_float(stats.max_seconds)}",
        "# HELP dns_probe_latency_mean_seconds Mean matched DNS latency in seconds.",
        "# TYPE dns_probe_latency_mean_seconds gauge",
        f"dns_probe_latency_mean_seconds{{{labels}}} {_format_float(stats.mean_seconds)}",
        "# HELP dns_probe_latency_median_seconds Median matched DNS latency in seconds.",
        "# TYPE dns_probe_latency_median_seconds gauge",
        (
            "dns_probe_latency_median_seconds"
            f"{{{labels}}} {_format_float(stats.median_seconds)}"
        ),
        "# HELP dns_probe_latency_stddev_seconds Stddev of matched DNS latency in seconds.",
        "# TYPE dns_probe_latency_stddev_seconds gauge",
        (
            "dns_probe_latency_stddev_seconds"
            f"{{{labels}}} {_format_float(stats.stdev_seconds)}"
        ),
        "# HELP dns_probe_latency_p95_seconds 95th percentile matched DNS latency in seconds.",
        "# TYPE dns_probe_latency_p95_seconds gauge",
        f"dns_probe_latency_p95_seconds{{{labels}}} {_format_float(stats.p95_seconds)}",
        "# HELP dns_probe_latency_p99_seconds 99th percentile matched DNS latency in seconds.",
        "# TYPE dns_probe_latency_p99_seconds gauge",
        f"dns_probe_latency_p99_seconds{{{labels}}} {_format_float(stats.p99_seconds)}",
        (
            "# HELP dns_probe_latency_over_1s_percent "
            "Percentage of matched responses above one second."
        ),
        "# TYPE dns_probe_latency_over_1s_percent gauge",
        (
            "dns_probe_latency_over_1s_percent"
            f"{{{labels}}} {_format_float(stats.pct_over_1s)}"
        ),
        "",
    ]
    temporary_path = output_path.with_suffix(f"{output_path.suffix}.tmp")
    temporary_path.write_text("\n".join(lines), encoding="utf-8")
    os.replace(temporary_path, output_path)
