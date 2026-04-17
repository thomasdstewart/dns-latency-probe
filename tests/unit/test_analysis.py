from dns_latency_probe.analysis import compute_latency_stats


def test_statistics_calculation() -> None:
    stats = compute_latency_stats(
        latencies=[0.1, 0.2, 1.5],
        total_queries_sent=5,
        unmatched_queries=2,
        late_responses=1,
        duplicate_response_candidates=0,
        out_of_order_responses=1,
        stale_responses=2,
    )

    assert stats.n == 3
    assert stats.min_seconds == 0.1
    assert stats.max_seconds == 1.5
    assert stats.p95_seconds == 1.5
    assert stats.p99_seconds == 1.5
    assert stats.pct_over_1s == (1 / 3) * 100
