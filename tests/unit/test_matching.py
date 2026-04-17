from dns_latency_probe.matching import match_dns_queries
from dns_latency_probe.models import QueryRecord, ResponseRecord


def test_matching_handles_duplicate_txid_safely() -> None:
    q1 = QueryRecord(1.0, 100, "example.com", 1, "udp", "1.1.1.1", 1234, "8.8.8.8", 53)
    q2 = QueryRecord(2.0, 100, "example.com", 1, "udp", "1.1.1.1", 1234, "8.8.8.8", 53)
    r1 = ResponseRecord(1.5, 100, "example.com", 1, "udp", "8.8.8.8", 53, "1.1.1.1", 1234)

    matched, unmatched, late, duplicates, out_of_order, stale = match_dns_queries(
        [q1, q2], [r1], late_threshold_seconds=1.0
    )

    assert len(matched) == 1
    assert matched[0].query.sent_at == 1.0
    assert len(unmatched) == 1
    assert late == 0
    assert duplicates == 0
    assert out_of_order == 0
    assert stale == 0


def test_matching_separates_duplicate_out_of_order_and_stale() -> None:
    q1 = QueryRecord(1.0, 100, "example.com", 1, "udp", "1.1.1.1", 1234, "8.8.8.8", 53)
    q2 = QueryRecord(2.0, 100, "example.com", 1, "udp", "1.1.1.1", 1234, "8.8.8.8", 53)

    responses = [
        ResponseRecord(0.5, 100, "example.com", 1, "udp", "8.8.8.8", 53, "1.1.1.1", 1234),
        ResponseRecord(1.5, 100, "example.com", 1, "udp", "8.8.8.8", 53, "1.1.1.1", 1234),
        ResponseRecord(1.6, 100, "example.com", 1, "udp", "8.8.8.8", 53, "1.1.1.1", 1234),
        ResponseRecord(3.0, 100, "example.com", 1, "udp", "8.8.8.8", 53, "1.1.1.1", 1234),
        ResponseRecord(3.1, 100, "example.com", 1, "udp", "8.8.8.8", 53, "1.1.1.1", 1234),
        ResponseRecord(4.0, 101, "example.com", 1, "udp", "8.8.8.8", 53, "1.1.1.1", 1234),
    ]

    matched, unmatched, late, duplicates, out_of_order, stale = match_dns_queries(
        [q1, q2], responses, late_threshold_seconds=1.0
    )

    assert len(matched) == 2
    assert len(unmatched) == 0
    assert late == 0
    assert duplicates == 2
    assert out_of_order == 1
    assert stale == 1
