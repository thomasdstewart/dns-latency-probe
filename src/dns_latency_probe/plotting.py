from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from dns_latency_probe.models import MatchedPair


def _plot_title(base_title: str, resolver: str, duration_seconds: float) -> str:
    return f"{base_title} (resolver={resolver}, duration={duration_seconds:g}s)"


def plot_latency_histogram(
    latencies: list[float], output_path: Path, resolver: str, duration_seconds: float
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(8, 4.5))
    plt.hist(latencies, bins=30, edgecolor="black")
    plt.title(_plot_title("DNS Response Time Histogram", resolver, duration_seconds))
    plt.xlabel("Latency (seconds)")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_latency_timeseries(
    matched: list[MatchedPair], output_path: Path, resolver: str, duration_seconds: float
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not matched:
        xs: list[float] = []
        ys: list[float] = []
    else:
        t0 = matched[0].query.sent_at
        xs = [pair.query.sent_at - t0 for pair in matched]
        ys = [pair.latency_seconds for pair in matched]

    plt.figure(figsize=(8, 4.5))
    plt.plot(xs, ys, marker="o", linestyle="none", markersize=3)
    plt.title(_plot_title("DNS Response Time Over Time", resolver, duration_seconds))
    plt.xlabel("Elapsed Time (seconds)")
    plt.ylabel("Latency (seconds)")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
