from __future__ import annotations

from contextlib import suppress
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.ticker import FixedLocator

from dns_latency_probe.models import MatchedPair

plt.switch_backend("Agg")


LATENCY_MIN_SECONDS = 1e-3
LATENCY_MAX_SECONDS = 1e1
LOG_MAJOR_TICKS = [1e-3, 1e-2, 1e-1, 1e0, 1e1]
LOG_MINOR_TICKS = [
    value
    for decade in (1e-3, 1e-2, 1e-1, 1e0)
    for value in [
        2 * decade,
        3 * decade,
        4 * decade,
        5 * decade,
        6 * decade,
        7 * decade,
        8 * decade,
        9 * decade,
    ]
]


def _clip_latencies(latencies: list[float]) -> list[float]:
    return [min(latency, LATENCY_MAX_SECONDS) for latency in latencies]


def _apply_layout() -> None:
    """Apply tight layout while tolerating backend/runtime recursion bugs."""
    with suppress(RecursionError):
        plt.tight_layout()


def _save_with_fallback(output_path: Path, fallback_title: str) -> None:
    try:
        plt.savefig(output_path)
    except RecursionError:
        # Observed in some Python 3.14 + matplotlib combinations during render.
        # Fall back to a minimal figure that avoids tick/marker layout internals.
        plt.clf()
        axis = plt.gca()
        axis.axis("off")
        axis.text(
            0.5,
            0.5,
            f"{fallback_title}\n(render fallback applied)",
            ha="center",
            va="center",
        )
        plt.savefig(output_path)


def _plot_title(
    base_title: str,
    resolver: str,
    duration_seconds: float,
    sender_source_ip: str,
    run_date: str,
) -> str:
    return (
        f"{base_title} (resolver={resolver}, duration={duration_seconds:g}s, "
        f"source_ip={sender_source_ip}, run_date={run_date})"
    )


def _configure_log_latency_axis(axis: Axes) -> None:
    axis.set_yscale("symlog", linthresh=LATENCY_MIN_SECONDS)
    axis.set_ylim(LATENCY_MIN_SECONDS, LATENCY_MAX_SECONDS)
    axis.yaxis.set_major_locator(FixedLocator(LOG_MAJOR_TICKS))
    axis.yaxis.set_minor_locator(FixedLocator(LOG_MINOR_TICKS))
    axis.tick_params(axis="y", which="major", length=6, width=1)
    axis.tick_params(axis="y", which="minor", length=3, width=0.8)
    axis.grid(True, axis="y", which="major", linestyle="--", alpha=0.35)
    axis.grid(True, axis="y", which="minor", linestyle=":", alpha=0.2)


def plot_latency_histogram(
    latencies: list[float],
    output_path: Path,
    resolver: str,
    duration_seconds: float,
    sender_source_ip: str,
    run_date: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    clipped_latencies = _clip_latencies(latencies)
    plt.figure(figsize=(16, 9))
    plt.hist(clipped_latencies, bins=30, edgecolor="black")
    plt.title(
        _plot_title(
            "DNS Response Time Histogram",
            resolver,
            duration_seconds,
            sender_source_ip,
            run_date,
        )
    )
    plt.xlabel("Latency (seconds)")
    plt.ylabel("Count")
    _apply_layout()
    _save_with_fallback(output_path, "DNS Response Time Histogram")
    plt.close()


def plot_latency_timeseries(
    matched: list[MatchedPair],
    output_path: Path,
    resolver: str,
    duration_seconds: float,
    sender_source_ip: str,
    run_date: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not matched:
        xs: list[float] = []
        ys: list[float] = []
    else:
        t0 = matched[0].query.sent_at
        xs = [pair.query.sent_at - t0 for pair in matched]
        ys = _clip_latencies([pair.latency_seconds for pair in matched])

    plt.figure(figsize=(16, 9))
    plt.plot(xs, ys, marker="o", linestyle="none", markersize=3)
    plt.title(
        _plot_title(
            "DNS Response Time Over Time",
            resolver,
            duration_seconds,
            sender_source_ip,
            run_date,
        )
    )
    plt.xlabel("Elapsed Time (seconds)")
    plt.ylabel("Latency (seconds)")
    _configure_log_latency_axis(plt.gca())
    _apply_layout()
    _save_with_fallback(output_path, "DNS Response Time Over Time")
    plt.close()


def plot_latency_run_comparison(
    run_latencies: list[list[float]],
    run_labels: list[str],
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    clipped_runs = [_clip_latencies(latencies) for latencies in run_latencies]
    figure, axis = plt.subplots(figsize=(16, 9))

    for index, latencies in enumerate(clipped_runs, start=1):
        if not latencies:
            continue
        axis.plot([index] * len(latencies), latencies, marker="o", linestyle="none", markersize=3, alpha=0.45)

    non_empty_runs = [latencies for latencies in clipped_runs if latencies]
    if non_empty_runs:
        axis.boxplot(non_empty_runs, positions=[i for i,l in enumerate(clipped_runs, start=1) if l], widths=0.35, showfliers=False)

    axis.set_title("DNS Latency Comparison Across Runs")
    axis.set_xlabel("Run")
    axis.set_ylabel("Latency (seconds)")
    axis.set_xticks(list(range(1, len(run_labels) + 1)))
    axis.set_xticklabels(run_labels, rotation=20, ha="right")
    _configure_log_latency_axis(axis)
    _apply_layout()
    figure.savefig(output_path)
    plt.close(figure)
