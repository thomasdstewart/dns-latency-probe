from __future__ import annotations

from contextlib import suppress
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from dns_latency_probe.models import MatchedPair

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


def plot_latency_histogram(
    latencies: list[float],
    output_path: Path,
    resolver: str,
    duration_seconds: float,
    sender_source_ip: str,
    run_date: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(16, 9))
    plt.hist(latencies, bins=30, edgecolor="black")
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
        ys = [pair.latency_seconds for pair in matched]

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
    plt.yscale("symlog", linthresh=1e-3)
    _apply_layout()
    _save_with_fallback(output_path, "DNS Response Time Over Time")
    plt.close()
