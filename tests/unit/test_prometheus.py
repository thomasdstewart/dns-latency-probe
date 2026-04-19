from pathlib import Path

from dns_latency_probe.analysis import LatencyStats
from dns_latency_probe.prometheus import write_prometheus_textfile


def _stats() -> LatencyStats:
    return LatencyStats(
        n=3,
        min_seconds=0.01,
        max_seconds=0.2,
        mean_seconds=0.08,
        median_seconds=0.05,
        stdev_seconds=0.04,
        p95_seconds=0.19,
        p99_seconds=0.199,
        pct_over_1s=0.0,
        total_queries_sent=10,
        matched_responses=9,
        unmatched_queries=1,
        late_responses=0,
        duplicate_response_candidates=0,
        out_of_order_responses=0,
        stale_responses=0,
    )


def test_write_prometheus_textfile_writes_atomic_metrics_file(tmp_path: Path) -> None:
    output_path = tmp_path / "dns.prom"

    write_prometheus_textfile(
        output_path=output_path,
        stats=_stats(),
        resolver='dns"google',
        resolver_port=53,
        output_base_name="baseline-a",
        run_started_unix=1_700_000_000,
    )

    contents = output_path.read_text(encoding="utf-8")
    assert 'resolver="dns\\"google"' in contents
    assert "dns_probe_run_success" in contents
    assert "dns_probe_latency_p99_seconds" in contents
    assert "dns_probe_last_run_unixtime" in contents
    assert not (tmp_path / "dns.prom.tmp").exists()
