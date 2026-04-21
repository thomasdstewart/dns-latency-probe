from contextlib import suppress
from pathlib import Path
from typing import List

import matplotlib.pyplot as plt

from dns_latency_probe.models import MatchedPair

plt.switch_backend("Agg")


LATENCY_MIN_SECONDS = 1e-3
LATENCY_MAX_SECONDS = 1e1


def _clip_latencies(latencies: List[float]) -> List[float]:
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


def plot_latency_histogram(
    latencies: List[float],
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
    matched: List[MatchedPair],
    output_path: Path,
    resolver: str,
    duration_seconds: float,
    sender_source_ip: str,
    run_date: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not matched:
        xs: List[float] = []
        ys: List[float] = []
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
    plt.yscale("symlog", linthresh=LATENCY_MIN_SECONDS)
    plt.ylim(LATENCY_MIN_SECONDS, LATENCY_MAX_SECONDS)
    _apply_layout()
    _save_with_fallback(output_path, "DNS Response Time Over Time")
    plt.close()
