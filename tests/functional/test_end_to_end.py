from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from scapy.utils import wrpcap

from dns_latency_probe.app import run_probe
from dns_latency_probe.config import ProbeConfig
from dns_latency_probe.models import QueryRecord


@dataclass(slots=True)
class FakeCaptureSession:
    packets: list[Packet]


class FakeDnsServer(threading.Thread):
    def __init__(self, host: str, port: int) -> None:
        super().__init__(daemon=True)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, port))
        self._running = True

    def run(self) -> None:
        while self._running:
            data, addr = self._sock.recvfrom(2048)
            dns = DNS(data)
            if dns.qr == 0 and dns.qd:
                reply = DNS(
                    id=dns.id,
                    qr=1,
                    aa=1,
                    rd=1,
                    ra=1,
                    qd=dns.qd,
                    an=DNSRR(rrname=dns.qd.qname, type="A", ttl=60, rdata="127.0.0.1"),
                )
                self._sock.sendto(bytes(reply), addr)

    def stop(self) -> None:
        self._running = False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wake:
            wake.sendto(b"\x00", self._sock.getsockname())
        self._sock.close()


def test_end_to_end_outputs_and_duration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\nexample.org\n", encoding="utf-8")

    capture_packets: list[Packet] = []

    def fake_start_capture(interface: str) -> FakeCaptureSession:
        assert interface == "lo"
        return FakeCaptureSession(capture_packets)

    def fake_stop_capture(session: FakeCaptureSession, pcap_path: Path) -> list[Packet]:
        wrpcap(str(pcap_path), session.packets)
        return session.packets

    server = FakeDnsServer("127.0.0.1", 1053)
    server.start()

    def fake_run_query_loop(
        *,
        domains: list[str],
        resolver: str,
        resolver_port: int,
        rate: float,
        stop_event: threading.Event,
        sent_queries: list[QueryRecord],
    ) -> None:
        i = 0
        while not stop_event.is_set():
            domain = domains[i % len(domains)]
            txid = i % 65536
            payload = bytes(DNS(id=txid, rd=1, qd=DNSQR(qname=domain, qtype="A")))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", 0))
                src_port = sock.getsockname()[1]
                q_time = time.time()
                sock.sendto(payload, (resolver, resolver_port))
                packet = (
                    IP(src="127.0.0.1", dst=resolver)
                    / UDP(sport=src_port, dport=resolver_port)
                    / DNS(payload)
                )
                packet.time = q_time
                capture_packets.append(packet)
                data, _ = sock.recvfrom(2048)
                r_time = time.time()
                response_packet = (
                    IP(src=resolver, dst="127.0.0.1")
                    / UDP(sport=resolver_port, dport=src_port)
                    / DNS(data)
                )
                response_packet.time = r_time
                capture_packets.append(response_packet)

            sent_queries.append(
                QueryRecord(
                    q_time, txid, domain, 1, "udp", "127.0.0.1", src_port, resolver, resolver_port
                )
            )
            i += 1
            time.sleep(1 / rate)

    monkeypatch.setattr("dns_latency_probe.app.start_capture", fake_start_capture)
    monkeypatch.setattr("dns_latency_probe.app.stop_capture", fake_stop_capture)
    monkeypatch.setattr("dns_latency_probe.app.run_query_loop", fake_run_query_loop)

    config = ProbeConfig(
        interface="lo",
        domains_file=domains_file,
        resolver="127.0.0.1",
        resolver_port=1053,
        rate=20,
        duration=0.3,
        output_dir=tmp_path / "out",
    )

    start = time.time()
    artifacts = run_probe(config)
    elapsed = time.time() - start
    server.stop()

    assert elapsed < 2.0
    assert artifacts.json_path.exists()
    assert artifacts.markdown_path.exists()
    assert artifacts.pdf_path.exists()
    assert artifacts.pcap_path.exists()
    assert artifacts.histogram_path.exists()
    assert artifacts.timeseries_path.exists()
    assert artifacts.json_path.name.endswith("_summary.json")
    assert artifacts.markdown_path.name.endswith("_report.md")
    assert artifacts.pdf_path.name.endswith("_report.pdf")
    assert artifacts.pcap_path.name.endswith("_capture.pcap")
    assert artifacts.histogram_path.name.endswith("_latency_histogram.png")
    assert artifacts.timeseries_path.name.endswith("_latency_timeseries.png")
    assert artifacts.stats.matched_responses > 0

    summary = json.loads(artifacts.json_path.read_text(encoding="utf-8"))
    assert "invocation_options" in summary
    assert "source_ips" in summary["invocation_options"]
    assert "127.0.0.1" in summary["invocation_options"]["source_ips"]
