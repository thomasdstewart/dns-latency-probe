from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from dns_latency_probe.app import _wait_for_probe_duration, run_probe
from dns_latency_probe.config import ProbeConfig


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
        pcap_path: Path,
    ) -> list[object]:
        nonlocal stop_capture_called
        stop_capture_called = True
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

    def raise_downstream_error(_packets: list[object]) -> tuple[list[object], list[object]]:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "dns_latency_probe.app.extract_dns_records",
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

    def fake_stop_capture(session: FakeCaptureSession, pcap_path: Path) -> list[object]:
        nonlocal stop_capture_called
        stop_capture_called = True
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

    def fake_stop_capture(session: FakeCaptureSession, pcap_path: Path) -> list[object]:
        del session
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

    def fake_extract_dns_records(_packets: list[object]) -> tuple[list[object], list[object]]:
        return [], []

    def fake_match_dns_queries(
        _queries: list[object], _responses: list[object]
    ) -> tuple[list[object], list[object], int, int]:
        return [], [], 0, 0

    def fail_if_sleep_called(_seconds: float) -> None:
        raise AssertionError("time.sleep should not be used for probe duration timing")

    monkeypatch.setattr("dns_latency_probe.app.start_capture", fake_start_capture)
    monkeypatch.setattr("dns_latency_probe.app.stop_capture", fake_stop_capture)
    monkeypatch.setattr("dns_latency_probe.app.run_query_loop", fake_run_query_loop)
    monkeypatch.setattr("dns_latency_probe.app.extract_dns_records", fake_extract_dns_records)
    monkeypatch.setattr("dns_latency_probe.app.match_dns_queries", fake_match_dns_queries)
    monkeypatch.setattr(
        "dns_latency_probe.app.write_json_summary", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        "dns_latency_probe.app.write_markdown_report", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        "dns_latency_probe.app.plot_latency_histogram", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        "dns_latency_probe.app.plot_latency_timeseries", lambda *args, **kwargs: None
    )
    monkeypatch.setattr("dns_latency_probe.app.write_pdf_report", lambda *args, **kwargs: None)
    monkeypatch.setattr("dns_latency_probe.app.time.sleep", fail_if_sleep_called)

    config = ProbeConfig(
        interface="lo",
        domains_file=domains_file,
        duration=0.01,
        output_dir=tmp_path / "out",
    )

    run_probe(config)
