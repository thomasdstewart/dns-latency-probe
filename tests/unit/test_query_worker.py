from __future__ import annotations

import threading

import pytest
from scapy.layers.dns import DNS
from scapy.packet import Packet

from dns_latency_probe.models import QueryRecord
from dns_latency_probe.query_worker import resolve_source_ip, run_query_loop


def test_resolve_source_ip_returns_none_for_unspecified_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "dns_latency_probe.query_worker.conf.route.route",
        lambda _resolver: ("0.0.0.0", "0.0.0.0", "0.0.0.0"),
    )

    assert resolve_source_ip("8.8.8.8") is None


def test_run_query_loop_records_resolved_source_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    stop_event = threading.Event()
    sent_queries: list[QueryRecord] = []

    monkeypatch.setattr("dns_latency_probe.query_worker.resolve_source_ip", lambda _resolver: None)
    monkeypatch.setattr("dns_latency_probe.query_worker.random.randint", lambda _a, _b: 12345)

    class NoOpRateLimiter:
        def __init__(self, _rate: float) -> None:
            pass

        def wait(self) -> None:
            return None

    monkeypatch.setattr("dns_latency_probe.query_worker.RateLimiter", NoOpRateLimiter)

    def fake_sender(packet: Packet) -> None:
        assert packet[DNS].id == 12345
        stop_event.set()

    run_query_loop(
        domains=["example.com"],
        resolver="8.8.8.8",
        resolver_port=53,
        rate=1000,
        stop_event=stop_event,
        sent_queries=sent_queries,
        sender=fake_sender,
    )

    assert len(sent_queries) == 1
    assert sent_queries[0].src_ip is None
