from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from dns_latency_probe.models import MatchedPair


def plot_latency_histogram(latencies: list[float], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(8, 4.5))
    plt.hist(latencies, bins=30, edgecolor="black")
    plt.title("DNS Response Time Histogram")
    plt.xlabel("Latency (seconds)")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_latency_timeseries(matched: list[MatchedPair], output_path: Path) -> None:
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
    plt.title("DNS Response Time Over Time")
    plt.xlabel("Elapsed Time (seconds)")
    plt.ylabel("Latency (seconds)")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
