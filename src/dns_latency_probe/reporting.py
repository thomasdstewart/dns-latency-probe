from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

from dns_latency_probe.analysis import LatencyStats

_SECONDS_DECIMALS = 6
_PERCENT_DECIMALS = 3

if TYPE_CHECKING:
    from collections.abc import Callable

    _PdfPagesFactory = Callable[[Path], PdfPages]
    PDF_PAGES_FACTORY: _PdfPagesFactory = PdfPages
else:
    PDF_PAGES_FACTORY = PdfPages


def _round_seconds(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, _SECONDS_DECIMALS)


def _round_percent(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, _PERCENT_DECIMALS)


def _format_seconds(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value:.{_SECONDS_DECIMALS}f} s"


def _format_percent(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value:.{_PERCENT_DECIMALS}f}%"


def write_json_summary(
    stats: LatencyStats, invocation_options: dict[str, object], output_path: Path
) -> None:
    report = {
        "invocation_options": invocation_options,
        "summary": {
            "total_queries_sent": stats.total_queries_sent,
            "matched_responses": stats.matched_responses,
            "unmatched_queries": stats.unmatched_queries,
            "late_responses": stats.late_responses,
            "duplicate_response_candidates": stats.duplicate_response_candidates,
            "out_of_order_responses": stats.out_of_order_responses,
            "stale_responses": stats.stale_responses,
        },
        "latency_statistics_seconds": {
            "unit": "seconds",
            "n": stats.n,
            "min": _round_seconds(stats.min_seconds),
            "max": _round_seconds(stats.max_seconds),
            "mean": _round_seconds(stats.mean_seconds),
            "median": _round_seconds(stats.median_seconds),
            "stddev": _round_seconds(stats.stdev_seconds),
            "p95": _round_seconds(stats.p95_seconds),
            "p99": _round_seconds(stats.p99_seconds),
            "pct_over_1s_percent": _round_percent(stats.pct_over_1s),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_markdown_report(
    stats: LatencyStats,
    output_path: Path,
    pcap_file: str,
    histogram_file: str,
    timeseries_file: str,
    pdf_file: str,
    sender_source_ip: str,
) -> None:
    lines = [
        "# DNS Latency Probe Report",
        "",
        "## Artifacts",
        f"- PCAP: `{pcap_file}`",
        f"- Histogram: `{histogram_file}`",
        f"- Time Series: `{timeseries_file}`",
        f"- PDF: `{pdf_file}`",
        "",
        "## Summary",
        f"- Total queries sent: {stats.total_queries_sent}",
        f"- Matched responses: {stats.matched_responses}",
        f"- Unmatched queries: {stats.unmatched_queries}",
        f"- Late responses (>1s): {stats.late_responses}",
        f"- Duplicate response candidates dropped: {stats.duplicate_response_candidates}",
        f"- Out-of-order responses: {stats.out_of_order_responses}",
        f"- Stale responses: {stats.stale_responses}",
        f"- Sender source IP(s): {sender_source_ip}",
        "",
        "## Latency Statistics",
        f"- n: {stats.n}",
        f"- min: {_format_seconds(stats.min_seconds)}",
        f"- max: {_format_seconds(stats.max_seconds)}",
        f"- mean: {_format_seconds(stats.mean_seconds)}",
        f"- median: {_format_seconds(stats.median_seconds)}",
        f"- stddev: {_format_seconds(stats.stdev_seconds)}",
        f"- p95: {_format_seconds(stats.p95_seconds)}",
        f"- p99: {_format_seconds(stats.p99_seconds)}",
        f"- > 1 s: {_format_percent(stats.pct_over_1s)}",
        "",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")


def _render_markdown_lines(markdown_path: Path) -> list[str]:
    markdown_contents = markdown_path.read_text(encoding="utf-8")
    return [line.rstrip() for line in markdown_contents.splitlines() if line.strip()]


def write_pdf_report(
    *,
    markdown_path: Path,
    histogram_path: Path,
    timeseries_path: Path,
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered_lines = _render_markdown_lines(markdown_path)

    with PDF_PAGES_FACTORY(output_path) as pdf:
        for start in range(0, len(rendered_lines), 45):
            fig, ax = plt.subplots(figsize=(8.27, 11.69))
            ax.axis("off")
            page_text = "\n".join(rendered_lines[start : start + 45])
            ax.text(0.02, 0.98, page_text, va="top", ha="left", family="monospace", fontsize=10)
            pdf.savefig(fig)
            plt.close(fig)

        for image_path, title in [
            (histogram_path, "Latency Histogram"),
            (timeseries_path, "Latency Time Series"),
        ]:
            image = plt.imread(image_path)
            fig, ax = plt.subplots(figsize=(11, 8.5))
            ax.imshow(image)
            ax.set_title(title)
            ax.axis("off")
            pdf.savefig(fig)
            plt.close(fig)
