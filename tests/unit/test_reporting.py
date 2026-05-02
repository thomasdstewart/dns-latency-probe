from __future__ import annotations

import json
from pathlib import Path

from dns_latency_probe.analysis import LatencyStats
from dns_latency_probe.reporting import write_json_summary, write_markdown_report


def _stats() -> LatencyStats:
    return LatencyStats(
        total_queries_sent=100,
        matched_responses=99,
        unmatched_queries=1,
        late_responses=2,
        duplicate_response_candidates=3,
        out_of_order_responses=4,
        stale_responses=5,
        n=99,
        min_seconds=0.123456789,
        max_seconds=1.0000004,
        mean_seconds=0.456789123,
        median_seconds=0.444444444,
        stdev_seconds=0.222222222,
        p95_seconds=0.987654321,
        p99_seconds=0.999999999,
        pct_over_1s=12.34567,
    )


def test_write_json_summary_rounds_float_values(tmp_path: Path) -> None:
    output_path = tmp_path / "summary.json"

    write_json_summary(_stats(), {"resolver": "1.1.1.1"}, output_path)

    report = json.loads(output_path.read_text(encoding="utf-8"))
    latency = report["latency_statistics_seconds"]

    assert latency["unit"] == "seconds"
    assert latency["min"] == 0.123457
    assert latency["max"] == 1.0
    assert latency["mean"] == 0.456789
    assert latency["pct_over_1s_percent"] == 12.346
    assert report["latencies_seconds"] == []


def test_write_markdown_report_formats_units_and_precision(tmp_path: Path) -> None:
    output_path = tmp_path / "report.md"

    write_markdown_report(
        _stats(),
        output_path,
        pcap_file="capture.pcap",
        histogram_file="hist.png",
        timeseries_file="timeseries.png",
        pdf_file="report.pdf",
        sender_source_ip="127.0.0.1",
    )

    markdown = output_path.read_text(encoding="utf-8")

    assert "## Latency Statistics" in markdown
    assert "- min: 0.123457 s" in markdown
    assert "- p99: 1.000000 s" in markdown
    assert "- > 1 s: 12.346%" in markdown


def test_write_json_summary_includes_latencies(tmp_path: Path) -> None:
    output_path = tmp_path / "summary.json"
    write_json_summary(
        _stats(),
        {"resolver": "1.1.1.1"},
        output_path,
        latencies_seconds=[0.12345678, 1.23456789],
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["latencies_seconds"] == [0.123457, 1.234568]
