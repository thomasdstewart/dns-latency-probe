from __future__ import annotations

import logging
import random
import threading
import time
from collections.abc import Callable

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from scapy.sendrecv import send

from dns_latency_probe.models import QueryRecord
from dns_latency_probe.utils import RateLimiter

LOGGER = logging.getLogger(__name__)

Sender = Callable[[Packet], None]


def default_sender(packet: Packet) -> None:
    send(packet, verbose=False)


def build_query_packet(
    *, txid: int, domain: str, resolver: str, resolver_port: int, src_port: int
) -> Packet:
    return (
        IP(dst=resolver)
        / UDP(sport=src_port, dport=resolver_port)
        / DNS(
            id=txid,
            rd=1,
            qd=DNSQR(qname=domain, qtype="A"),
        )
    )


def run_query_loop(
    *,
    domains: list[str],
    resolver: str,
    resolver_port: int,
    rate: float,
    stop_event: threading.Event,
    sent_queries: list[QueryRecord],
    expected_queries: int | None = None,
    sender: Sender = default_sender,
) -> None:
    limiter = RateLimiter(rate)
    index = 0
    report_interval_seconds = 5.0
    next_report_at = time.monotonic() + report_interval_seconds

    while not stop_event.is_set():
        domain = domains[index % len(domains)]
        txid = random.randint(0, 65535)
        src_port = random.randint(1024, 65535)
        packet = build_query_packet(
            txid=txid,
            domain=domain,
            resolver=resolver,
            resolver_port=resolver_port,
            src_port=src_port,
        )
        sent_at = time.time()
        sender(packet)
        sent_queries.append(
            QueryRecord(
                sent_at=sent_at,
                txid=txid,
                qname=domain.rstrip(".").lower(),
                qtype=1,
                protocol="udp",
                src_ip="0.0.0.0",
                src_port=src_port,
                dst_ip=resolver,
                dst_port=resolver_port,
            )
        )
        index += 1
        now = time.monotonic()
        if now >= next_report_at:
            if expected_queries and expected_queries > 0:
                progress_pct = min((index / expected_queries) * 100, 100.0)
                LOGGER.info(
                    "Query sender progress: sent %d/%d queries (%.1f%%)",
                    index,
                    expected_queries,
                    progress_pct,
                )
            else:
                LOGGER.info("Query sender progress: sent %d queries", index)
            next_report_at = now + report_interval_seconds
        limiter.wait()
    LOGGER.info("Query worker stopped after sending %d queries", index)
