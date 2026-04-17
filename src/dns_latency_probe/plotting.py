from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from dns_latency_probe.models import MatchedPair

MAX_PLOT_LATENCY_SECONDS = 10.0


def _clip_latency_seconds(latency_seconds: float) -> float:
    return min(latency_seconds, MAX_PLOT_LATENCY_SECONDS)


def _plot_title(
    base_title: str, resolver: str, duration_seconds: float, sender_source_ip: str
) -> str:
    return (
        f"{base_title} (resolver={resolver}, duration={duration_seconds:g}s, "
        f"source_ip={sender_source_ip})"
    )


def plot_latency_histogram(
    latencies: list[float],
    output_path: Path,
    resolver: str,
    duration_seconds: float,
    sender_source_ip: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    clipped_latencies = [_clip_latency_seconds(latency) for latency in latencies]
    plt.figure(figsize=(8, 4.5))
    plt.hist(clipped_latencies, bins=30, edgecolor="black")
    plt.title(
        _plot_title(
            "DNS Response Time Histogram",
            resolver,
            duration_seconds,
            sender_source_ip,
        )
    )
    plt.xlabel("Latency (seconds)")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_latency_timeseries(
    matched: list[MatchedPair],
    output_path: Path,
    resolver: str,
    duration_seconds: float,
    sender_source_ip: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not matched:
        xs: list[float] = []
        ys: list[float] = []
    else:
        t0 = matched[0].query.sent_at
        xs = [pair.query.sent_at - t0 for pair in matched]
        ys = [_clip_latency_seconds(pair.latency_seconds) for pair in matched]

    plt.figure(figsize=(8, 4.5))
    plt.plot(xs, ys, marker="o", linestyle="none", markersize=3)
    plt.title(
        _plot_title(
            "DNS Response Time Over Time",
            resolver,
            duration_seconds,
            sender_source_ip,
        )
    )
    plt.xlabel("Elapsed Time (seconds)")
    plt.ylabel("Latency (seconds)")
    plt.yscale("symlog", linthresh=1e-3)
    plt.ylim(0, MAX_PLOT_LATENCY_SECONDS)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
