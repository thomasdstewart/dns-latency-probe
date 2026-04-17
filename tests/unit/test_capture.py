from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from dns_latency_probe.capture import extract_dns_records


def test_extract_dns_records_uses_first_question_from_packet_list() -> None:
    packet = (
        IP(src="127.0.0.1", dst="8.8.8.8")
        / UDP(sport=55000, dport=53)
        / DNS(id=11, qr=0, qd=[DNSQR(qname="Example.COM", qtype="A")])
    )
    packet.time = 123.0

    queries, responses = extract_dns_records([packet])

    assert len(queries) == 1
    assert responses == []
    assert queries[0].qname == "example.com"
    assert queries[0].qtype == 1


def test_extract_dns_records_skips_packets_with_empty_question_list() -> None:
    packet = (
        IP(src="127.0.0.1", dst="8.8.8.8") / UDP(sport=55000, dport=53) / DNS(id=12, qr=0, qd=[])
    )
    packet[DNS].qdcount = 1

    queries, responses = extract_dns_records([packet])

    assert queries == []
    assert responses == []
