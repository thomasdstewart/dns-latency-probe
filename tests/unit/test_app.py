from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from dns_latency_probe.app import _wait_for_probe_duration, run_probe
from dns_latency_probe.config import ProbeConfig
from dns_latency_probe.models import MatchedPair, QueryRecord, ResponseRecord
from dns_latency_probe.tshark import TsharkDnsAnalysis


def test_run_probe_stops_worker_and_capture_on_downstream_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    class FakeCaptureSession:
        pass

    stop_capture_called = False
    worker_stopped = threading.Event()

    def fake_start_capture(interface: str) -> FakeCaptureSession:
        assert interface == "lo"
        return FakeCaptureSession()

    def fake_stop_capture(
        session: FakeCaptureSession,
        pcap_path: Path | None,
    ) -> list[object]:
        nonlocal stop_capture_called
        del session
        stop_capture_called = True
        assert pcap_path is not None
        assert pcap_path.name.endswith(".pcap")
        return []

    def fake_run_query_loop(
        *,
        domains: list[str],
        resolver: str,
        resolver_port: int,
        rate: float,
        stop_event: threading.Event,
        sent_queries: list[object],
        expected_queries: int | None = None,
    ) -> None:
        assert domains == ["example.com"]
        assert resolver == "127.0.0.1"
        assert resolver_port == 53
        assert rate == 10.0
        stop_event.wait(timeout=1)
        if stop_event.is_set():
            worker_stopped.set()

    monkeypatch.setattr("dns_latency_probe.app.start_capture", fake_start_capture)
    monkeypatch.setattr("dns_latency_probe.app.stop_capture", fake_stop_capture)
    monkeypatch.setattr("dns_latency_probe.app.run_query_loop", fake_run_query_loop)

    def raise_downstream_error(_pcap_path: Path) -> TsharkDnsAnalysis:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "dns_latency_probe.app.analyse_pcap_with_tshark",
        raise_downstream_error,
    )

    config = ProbeConfig(
        interface="lo",
        domains_file=domains_file,
        duration=0.01,
        output_dir=tmp_path / "out",
    )

    with pytest.raises(RuntimeError, match="boom"):
        run_probe(config)

    assert stop_capture_called
    assert worker_stopped.is_set()


def test_run_probe_stops_capture_when_worker_start_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    class FakeCaptureSession:
        pass

    class FailingThread:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def start(self) -> None:
            raise RuntimeError("can't start new thread")

        def join(self, timeout: float | None = None) -> None:
            del timeout
            raise AssertionError("join must not be called before a successful start")

    stop_capture_called = False

    def fake_start_capture(interface: str) -> FakeCaptureSession:
        assert interface == "lo"
        return FakeCaptureSession()

    def fake_stop_capture(session: FakeCaptureSession, pcap_path: Path | None) -> list[object]:
        nonlocal stop_capture_called
        del session
        stop_capture_called = True
        assert pcap_path is not None
        assert pcap_path.name.endswith(".pcap")
        return []

    monkeypatch.setattr("dns_latency_probe.app.start_capture", fake_start_capture)
    monkeypatch.setattr("dns_latency_probe.app.stop_capture", fake_stop_capture)
    monkeypatch.setattr("dns_latency_probe.app.threading.Thread", FailingThread)

    config = ProbeConfig(
        interface="lo",
        domains_file=domains_file,
        duration=0.01,
        output_dir=tmp_path / "out",
    )

    with pytest.raises(RuntimeError, match="can't start new thread"):
        run_probe(config)

    assert stop_capture_called


def test_wait_for_probe_duration_returns_when_worker_stops() -> None:
    stop_event = threading.Event()
    worker_stopped = threading.Event()

    def worker_target() -> None:
        worker_stopped.wait(timeout=1)

    worker = threading.Thread(target=worker_target)
    worker.start()
    worker_stopped.set()
    worker.join(timeout=1)

    started = time.monotonic()
    _wait_for_probe_duration(duration_seconds=10, stop_event=stop_event, worker=worker)
    elapsed = time.monotonic() - started

    assert elapsed < 0.1


def test_run_probe_uses_deadline_wait_not_time_sleep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    class FakeCaptureSession:
        pass

    def fake_start_capture(interface: str) -> FakeCaptureSession:
        assert interface == "lo"
        return FakeCaptureSession()

    def fake_stop_capture(session: FakeCaptureSession, pcap_path: Path | None) -> list[object]:
        del session
        assert pcap_path is not None
        assert pcap_path.name.endswith(".pcap")
        return []

    def fake_run_query_loop(
        *,
        domains: list[str],
        resolver: str,
        resolver_port: int,
        rate: float,
        stop_event: threading.Event,
        sent_queries: list[object],
        expected_queries: int | None = None,
    ) -> None:
        del domains, resolver, resolver_port, rate, sent_queries, expected_queries
        stop_event.wait(timeout=1)

    def fake_analyse_pcap_with_tshark(_pcap_path: Path) -> TsharkDnsAnalysis:
        return TsharkDnsAnalysis([], [], [], 0, 0, 0, 0)

    def no_op(*_args: object, **_kwargs: object) -> None:
        return None

    def fail_if_sleep_called(_seconds: float) -> None:
        raise AssertionError("time.sleep should not be used for probe duration timing")

    monkeypatch.setattr("dns_latency_probe.app.start_capture", fake_start_capture)
    monkeypatch.setattr("dns_latency_probe.app.stop_capture", fake_stop_capture)
    monkeypatch.setattr("dns_latency_probe.app.run_query_loop", fake_run_query_loop)
    monkeypatch.setattr(
        "dns_latency_probe.app.analyse_pcap_with_tshark", fake_analyse_pcap_with_tshark
    )
    monkeypatch.setattr("dns_latency_probe.app.write_json_summary", no_op)
    monkeypatch.setattr("dns_latency_probe.app.write_markdown_report", no_op)
    monkeypatch.setattr("dns_latency_probe.app.plot_latency_histogram", no_op)
    monkeypatch.setattr("dns_latency_probe.app.plot_latency_timeseries", no_op)
    monkeypatch.setattr("dns_latency_probe.app.write_pdf_report", no_op)
    monkeypatch.setattr("dns_latency_probe.app.time.sleep", fail_if_sleep_called)

    config = ProbeConfig(
        interface="lo",
        domains_file=domains_file,
        duration=0.01,
        output_dir=tmp_path / "out",
    )

    run_probe(config)


def test_run_probe_prometheus_mode_disables_report_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    class FakeCaptureSession:
        pass

    stop_capture_pcap_path: Path | None = tmp_path / "will-be-overwritten"
    report_emit_attempted = False
    prom_emit_called = False

    def fake_start_capture(interface: str) -> FakeCaptureSession:
        assert interface == "lo"
        return FakeCaptureSession()

    def fake_stop_capture(session: FakeCaptureSession, pcap_path: Path | None) -> list[object]:
        nonlocal stop_capture_pcap_path
        del session
        stop_capture_pcap_path = pcap_path
        return []

    def fake_run_query_loop(
        *,
        domains: list[str],
        resolver: str,
        resolver_port: int,
        rate: float,
        stop_event: threading.Event,
        sent_queries: list[object],
        expected_queries: int | None = None,
    ) -> None:
        del domains, resolver, resolver_port, rate, sent_queries, expected_queries
        stop_event.wait(timeout=1)

    def fake_analyse_pcap_with_tshark(_pcap_path: Path) -> TsharkDnsAnalysis:
        return TsharkDnsAnalysis([], [], [], 0, 0, 0, 0)

    def fail_report_emit(*_args: object, **_kwargs: object) -> None:
        nonlocal report_emit_attempted
        report_emit_attempted = True

    def fake_write_prometheus_textfile(**_kwargs: object) -> None:
        nonlocal prom_emit_called
        prom_emit_called = True

    monkeypatch.setattr("dns_latency_probe.app.start_capture", fake_start_capture)
    monkeypatch.setattr("dns_latency_probe.app.stop_capture", fake_stop_capture)
    monkeypatch.setattr("dns_latency_probe.app.run_query_loop", fake_run_query_loop)
    monkeypatch.setattr(
        "dns_latency_probe.app.analyse_pcap_with_tshark", fake_analyse_pcap_with_tshark
    )
    monkeypatch.setattr("dns_latency_probe.app.write_json_summary", fail_report_emit)
    monkeypatch.setattr("dns_latency_probe.app.write_markdown_report", fail_report_emit)
    monkeypatch.setattr("dns_latency_probe.app.plot_latency_histogram", fail_report_emit)
    monkeypatch.setattr("dns_latency_probe.app.plot_latency_timeseries", fail_report_emit)
    monkeypatch.setattr("dns_latency_probe.app.write_pdf_report", fail_report_emit)
    monkeypatch.setattr(
        "dns_latency_probe.app.write_prometheus_textfile",
        fake_write_prometheus_textfile,
    )

    config = ProbeConfig(
        interface="lo",
        domains_file=domains_file,
        duration=0.01,
        resolver="8.8.8.8",
        output_format="prometheus",
        output_dir=tmp_path / "out",
        prometheus_dir=tmp_path / "metrics",
    )

    artifacts = run_probe(config)

    assert stop_capture_pcap_path is not None
    assert stop_capture_pcap_path.name.endswith(".pcap")
    assert prom_emit_called
    assert not report_emit_attempted
    assert artifacts.prometheus_path.name == "8-8-8-8.prom"


def test_run_probe_propagates_tshark_duplicate_and_stale_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    class FakeCaptureSession:
        pass

    query = QueryRecord(1.0, 100, "example.com", 1, "udp", "127.0.0.1", 12345, "8.8.8.8", 53)
    response = ResponseRecord(1.2, 100, "example.com", 1, "udp", "8.8.8.8", 53, "127.0.0.1", 12345)

    def fake_start_capture(_interface: str) -> FakeCaptureSession:
        return FakeCaptureSession()

    def fake_stop_capture(_session: FakeCaptureSession, pcap_path: Path | None) -> list[object]:
        assert pcap_path is not None
        return []

    def fake_run_query_loop(
        *,
        domains: list[str],
        resolver: str,
        resolver_port: int,
        rate: float,
        stop_event: threading.Event,
        sent_queries: list[QueryRecord],
        expected_queries: int | None = None,
    ) -> None:
        del domains, resolver, resolver_port, rate, stop_event, expected_queries
        sent_queries.append(query)

    def fake_analyse_pcap_with_tshark(_pcap_path: Path) -> TsharkDnsAnalysis:
        return TsharkDnsAnalysis(
            queries=[query],
            matched=[MatchedPair(query, response, 0.2)],
            unmatched=[],
            responses_without_tshark_latency=1,
            duplicate_response_candidates=2,
            stale_responses=3,
            malformed_rows=0,
        )

    def no_op(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr("dns_latency_probe.app.start_capture", fake_start_capture)
    monkeypatch.setattr("dns_latency_probe.app.stop_capture", fake_stop_capture)
    monkeypatch.setattr("dns_latency_probe.app.run_query_loop", fake_run_query_loop)
    monkeypatch.setattr(
        "dns_latency_probe.app.analyse_pcap_with_tshark", fake_analyse_pcap_with_tshark
    )
    monkeypatch.setattr("dns_latency_probe.app.write_json_summary", no_op)
    monkeypatch.setattr("dns_latency_probe.app.write_markdown_report", no_op)
    monkeypatch.setattr("dns_latency_probe.app.plot_latency_histogram", no_op)
    monkeypatch.setattr("dns_latency_probe.app.plot_latency_timeseries", no_op)
    monkeypatch.setattr("dns_latency_probe.app.write_pdf_report", no_op)

    artifacts = run_probe(
        ProbeConfig(interface="lo", domains_file=domains_file, output_dir=tmp_path / "out")
    )

    assert artifacts.stats.matched_responses == 1
    assert artifacts.stats.duplicate_response_candidates == 2
    assert artifacts.stats.stale_responses == 3
