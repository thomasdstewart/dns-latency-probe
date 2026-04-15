from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from statistics import mean, median, pstdev


@dataclass(slots=True)
class LatencyStats:
    total_queries_sent: int
    matched_responses: int
    unmatched_queries: int
    late_responses: int
    duplicate_response_candidates: int
    n: int
    min_seconds: float | None
    max_seconds: float | None
    mean_seconds: float | None
    median_seconds: float | None
    stdev_seconds: float | None
    p95_seconds: float | None
    p99_seconds: float | None
    pct_over_1s: float | None

    def to_dict(self) -> dict[str, float | int | None]:
        return asdict(self)


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        raise ValueError("values must not be empty")
    index = math.ceil((pct / 100.0) * len(sorted_values)) - 1
    index = max(0, min(index, len(sorted_values) - 1))
    return sorted_values[index]


def compute_latency_stats(
    *,
    latencies: list[float],
    total_queries_sent: int,
    unmatched_queries: int,
    late_responses: int,
    duplicate_response_candidates: int,
) -> LatencyStats:
    if not latencies:
        return LatencyStats(
            total_queries_sent=total_queries_sent,
            matched_responses=0,
            unmatched_queries=unmatched_queries,
            late_responses=late_responses,
            duplicate_response_candidates=duplicate_response_candidates,
            n=0,
            min_seconds=None,
            max_seconds=None,
            mean_seconds=None,
            median_seconds=None,
            stdev_seconds=None,
            p95_seconds=None,
            p99_seconds=None,
            pct_over_1s=None,
        )

    ordered = sorted(latencies)
    over_1s = sum(1 for x in latencies if x > 1.0)
    return LatencyStats(
        total_queries_sent=total_queries_sent,
        matched_responses=len(latencies),
        unmatched_queries=unmatched_queries,
        late_responses=late_responses,
        duplicate_response_candidates=duplicate_response_candidates,
        n=len(latencies),
        min_seconds=min(ordered),
        max_seconds=max(ordered),
        mean_seconds=mean(ordered),
        median_seconds=median(ordered),
        stdev_seconds=pstdev(ordered),
        p95_seconds=_percentile(ordered, 95),
        p99_seconds=_percentile(ordered, 99),
        pct_over_1s=(over_1s / len(ordered)) * 100.0,
    )
