from dns_latency_probe.capture import dns_bpf_filter


def test_dns_bpf_filter_captures_udp_and_tcp_dns() -> None:
    assert dns_bpf_filter() == "(udp port 53 or tcp port 53)"
