from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pytest
from matplotlib.ticker import FixedLocator

from dns_latency_probe.models import MatchedPair, QueryRecord, ResponseRecord
from dns_latency_probe.plotting import (
    LOG_MAJOR_TICKS,
    LOG_MINOR_TICKS,
    _configure_log_latency_axis,
    plot_latency_histogram,
    plot_latency_run_comparison,
    plot_latency_timeseries,
)


def _matched_pair() -> MatchedPair:
    query = QueryRecord(
        sent_at=1_700_000_000.0,
        txid=1,
        qname="example.com",
        qtype=1,
        protocol="udp",
        src_ip="127.0.0.1",
        src_port=53000,
        dst_ip="127.0.0.1",
        dst_port=53,
    )
    response = ResponseRecord(
        seen_at=1_700_000_000.01,
        txid=1,
        qname="example.com",
        qtype=1,
        protocol="udp",
        src_ip="127.0.0.1",
        src_port=53,
        dst_ip="127.0.0.1",
        dst_port=53000,
    )
    return MatchedPair(query=query, response=response, latency_seconds=0.01)


@pytest.mark.parametrize("output_name", ["hist.png", "timeseries.png"])
def test_plotting_handles_tight_layout_recursion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output_name: str
) -> None:
    def raise_recursion() -> None:
        raise RecursionError("simulated matplotlib recursion")

    monkeypatch.setattr(plt, "tight_layout", raise_recursion)

    output_path = tmp_path / output_name
    if output_name == "hist.png":
        plot_latency_histogram(
            latencies=[0.01, 0.02, 0.03],
            output_path=output_path,
            resolver="127.0.0.1",
            duration_seconds=1.0,
            sender_source_ip="127.0.0.1",
            run_date="2026-04-17",
        )
    else:
        plot_latency_timeseries(
            matched=[_matched_pair()],
            output_path=output_path,
            resolver="127.0.0.1",
            duration_seconds=1.0,
            sender_source_ip="127.0.0.1",
            run_date="2026-04-17",
        )

    assert output_path.exists()


def test_plotting_handles_savefig_recursion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_savefig = plt.savefig
    savefig_calls = 0

    def flaky_savefig(*args: object, **kwargs: object) -> None:
        nonlocal savefig_calls
        savefig_calls += 1
        if savefig_calls == 1:
            raise RecursionError("simulated save recursion")
        original_savefig(*args, **kwargs)

    monkeypatch.setattr(plt, "savefig", flaky_savefig)

    output_path = tmp_path / "fallback.png"
    plot_latency_histogram(
        latencies=[0.01, 0.02, 0.03],
        output_path=output_path,
        resolver="127.0.0.1",
        duration_seconds=1.0,
        sender_source_ip="127.0.0.1",
        run_date="2026-04-17",
    )

    assert savefig_calls == 2
    assert output_path.exists()


def test_plotting_preserves_high_latency_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    histogram_inputs: list[float] = []
    timeseries_inputs: list[float] = []

    def capture_hist(values: list[float], *args: object, **kwargs: object) -> None:
        _ = (args, kwargs)
        histogram_inputs.extend(values)

    def capture_plot(*args: object, **kwargs: object) -> None:
        _ = kwargs
        if len(args) >= 2:
            ys = args[1]
            if isinstance(ys, list):
                timeseries_inputs.extend(ys)

    monkeypatch.setattr(plt, "hist", capture_hist)
    monkeypatch.setattr(plt, "plot", capture_plot)

    output_histogram = tmp_path / "high-latency-hist.png"
    output_timeseries = tmp_path / "high-latency-series.png"

    plot_latency_histogram(
        latencies=[0.01, 12.5],
        output_path=output_histogram,
        resolver="127.0.0.1",
        duration_seconds=1.0,
        sender_source_ip="127.0.0.1",
        run_date="2026-04-17",
    )
    plot_latency_timeseries(
        matched=[
            _matched_pair(),
            MatchedPair(
                query=QueryRecord(
                    sent_at=1_700_000_001.0,
                    txid=2,
                    qname="example.org",
                    qtype=1,
                    protocol="udp",
                    src_ip="127.0.0.1",
                    src_port=53001,
                    dst_ip="127.0.0.1",
                    dst_port=53,
                ),
                response=ResponseRecord(
                    seen_at=1_700_000_013.5,
                    txid=2,
                    qname="example.org",
                    qtype=1,
                    protocol="udp",
                    src_ip="127.0.0.1",
                    src_port=53,
                    dst_ip="127.0.0.1",
                    dst_port=53001,
                ),
                latency_seconds=12.5,
            ),
        ],
        output_path=output_timeseries,
        resolver="127.0.0.1",
        duration_seconds=1.0,
        sender_source_ip="127.0.0.1",
        run_date="2026-04-17",
    )

    assert 10.0 in histogram_inputs
    assert 10.0 in timeseries_inputs


def test_plotting_preserves_low_latency_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    timeseries_inputs: list[float] = []

    def capture_plot(*args: object, **kwargs: object) -> None:
        _ = kwargs
        if len(args) >= 2:
            ys = args[1]
            if isinstance(ys, list):
                timeseries_inputs.extend(ys)

    monkeypatch.setattr(plt, "plot", capture_plot)

    output_timeseries = tmp_path / "low-latency-series.png"
    plot_latency_timeseries(
        matched=[
            MatchedPair(
                query=QueryRecord(
                    sent_at=1_700_000_000.0,
                    txid=1,
                    qname="example.com",
                    qtype=1,
                    protocol="udp",
                    src_ip="127.0.0.1",
                    src_port=53000,
                    dst_ip="127.0.0.1",
                    dst_port=53,
                ),
                response=ResponseRecord(
                    seen_at=1_700_000_000.0001,
                    txid=1,
                    qname="example.com",
                    qtype=1,
                    protocol="udp",
                    src_ip="127.0.0.1",
                    src_port=53,
                    dst_ip="127.0.0.1",
                    dst_port=53000,
                ),
                latency_seconds=1e-4,
            )
        ],
        output_path=output_timeseries,
        resolver="127.0.0.1",
        duration_seconds=1.0,
        sender_source_ip="127.0.0.1",
        run_date="2026-04-17",
    )

    assert 1e-4 in timeseries_inputs


def test_configure_log_latency_axis_adds_major_and_minor_ticks() -> None:
    figure, axis = plt.subplots()
    _configure_log_latency_axis(axis)

    major_locator = axis.yaxis.get_major_locator()
    minor_locator = axis.yaxis.get_minor_locator()

    assert isinstance(major_locator, FixedLocator)
    assert isinstance(minor_locator, FixedLocator)
    assert list(major_locator.tick_values(0.0, 1.0)) == LOG_MAJOR_TICKS
    assert list(minor_locator.tick_values(0.0, 1.0)) == LOG_MINOR_TICKS

    plt.close(figure)


def test_plot_latency_run_comparison_creates_image(tmp_path: Path) -> None:
    output_path = tmp_path / "comparison.png"
    plot_latency_run_comparison([[0.01, 0.1], [0.02, 0.2, 2.0]], ["run-a", "run-b"], output_path)
    assert output_path.exists()
