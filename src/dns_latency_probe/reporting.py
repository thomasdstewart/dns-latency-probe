from __future__ import annotations

import json
import subprocess
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

from dns_latency_probe.analysis import LatencyStats


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
        },
        "latency_statistics_seconds": {
            "n": stats.n,
            "min": stats.min_seconds,
            "max": stats.max_seconds,
            "mean": stats.mean_seconds,
            "median": stats.median_seconds,
            "stddev": stats.stdev_seconds,
            "p95": stats.p95_seconds,
            "p99": stats.p99_seconds,
            "pct_over_1s": stats.pct_over_1s,
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
        f"- Sender source IP(s): {sender_source_ip}",
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


def _render_markdown_lines(markdown_path: Path) -> list[str]:
    command = ["pandoc", "--from", "markdown", "--to", "plain", str(markdown_path)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("Pandoc is required to render markdown for the PDF report.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Pandoc failed to render markdown: {exc.stderr.strip()}") from exc

    return [line.rstrip() for line in result.stdout.splitlines() if line.strip()]


def write_pdf_report(
    *,
    markdown_path: Path,
    histogram_path: Path,
    timeseries_path: Path,
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered_lines = _render_markdown_lines(markdown_path)

    with PdfPages(output_path) as pdf:
        for start in range(0, len(rendered_lines), 45):
            fig, ax = plt.subplots(figsize=(8.27, 11.69))
            ax.axis("off")
            page_text = "\n".join(rendered_lines[start : start + 45])
            ax.text(0.02, 0.98, page_text, va="top", ha="left", family="monospace", fontsize=10)
            pdf.savefig(fig, bbox_inches="tight")
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
            pdf.savefig(fig, bbox_inches="tight")
            plt.close(fig)
