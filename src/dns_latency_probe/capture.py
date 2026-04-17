from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.utils import wrpcap

from dns_latency_probe.models import QueryRecord, ResponseRecord

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class CaptureSession:
    sniffer: AsyncSniffer
    packets: list[Packet]
    packets_lock: threading.Lock
    packet_count: list[int]
    reporter_stop_event: threading.Event
    reporter_thread: threading.Thread


def dns_bpf_filter() -> str:
    return "(udp port 53 or tcp port 53)"


def start_capture(interface: str) -> CaptureSession:
    packets: list[Packet] = []
    packets_lock = threading.Lock()
    packet_count = [0]
    ready = threading.Event()
    reporter_stop_event = threading.Event()
    report_interval_seconds = 5.0

    def handle_packet(packet: Packet) -> None:
        with packets_lock:
            packets.append(packet)
            packet_count[0] += 1

    def report_capture_progress() -> None:
        while not reporter_stop_event.wait(report_interval_seconds):
            with packets_lock:
                current_count = packet_count[0]
            LOGGER.info("Capture progress: received %d packets", current_count)

    sniffer = AsyncSniffer(iface=interface, filter=dns_bpf_filter(), prn=handle_packet, store=False)
    sniffer.start()
    reporter_thread = threading.Thread(
        target=report_capture_progress,
        daemon=True,
        name="dns-capture-progress",
    )
    reporter_thread.start()
    for _ in range(100):
        if sniffer.running:
            ready.set()
            break
        time.sleep(0.01)
    if not ready.is_set():
        reporter_stop_event.set()
        reporter_thread.join(timeout=1)
        raise RuntimeError("packet capture did not start in time")
    LOGGER.info("Started capture on interface %s", interface)
    return CaptureSession(
        sniffer=sniffer,
        packets=packets,
        packets_lock=packets_lock,
        packet_count=packet_count,
        reporter_stop_event=reporter_stop_event,
        reporter_thread=reporter_thread,
    )


def stop_capture(session: CaptureSession, pcap_path: Path) -> list[Packet]:
    session.reporter_stop_event.set()
    session.reporter_thread.join(timeout=1)
    session.sniffer.stop(join=True)
    with session.packets_lock:
        packets = list(session.packets)
        packet_count = session.packet_count[0]
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(pcap_path), packets)
    LOGGER.info("Saved %d captured packets to %s", packet_count, pcap_path)
    return packets


def _qname_from_question(question: DNSQR) -> str:
    qname_raw = question.qname
    qname = str(qname_raw.decode("utf-8", errors="ignore").rstrip(".").lower())
    return qname


def _first_dns_question(dns: DNS) -> DNSQR | None:
    qd = dns.qd
    if qd is None:
        return None
    if isinstance(qd, DNSQR):
        return qd
    try:
        first = qd[0]
    except (IndexError, TypeError):
        return None
    if isinstance(first, DNSQR):
        return first
    return None


def extract_dns_records(packets: list[Packet]) -> tuple[list[QueryRecord], list[ResponseRecord]]:
    queries: list[QueryRecord] = []
    responses: list[ResponseRecord] = []

    for packet in packets:
        if DNS not in packet or IP not in packet:
            continue
        dns = packet[DNS]
        question = _first_dns_question(dns)
        if question is None:
            continue

        protocol: str
        src_port: int
        dst_port: int
        if UDP in packet:
            protocol = "udp"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif TCP in packet:
            protocol = "tcp"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        else:
            continue

        qname = _qname_from_question(question)
        qtype = int(question.qtype)
        timestamp = float(getattr(packet, "time", 0.0))

        if dns.qr == 0:
            queries.append(
                QueryRecord(
                    sent_at=timestamp,
                    txid=int(dns.id),
                    qname=qname,
                    qtype=qtype,
                    protocol=protocol,
                    src_ip=str(packet[IP].src),
                    src_port=src_port,
                    dst_ip=str(packet[IP].dst),
                    dst_port=dst_port,
                )
            )
        else:
            responses.append(
                ResponseRecord(
                    seen_at=timestamp,
                    txid=int(dns.id),
                    qname=qname,
                    qtype=qtype,
                    protocol=protocol,
                    src_ip=str(packet[IP].src),
                    src_port=src_port,
                    dst_ip=str(packet[IP].dst),
                    dst_port=dst_port,
                )
            )

    return queries, responses
