from dns_latency_probe.matching import match_dns_queries
from dns_latency_probe.models import QueryRecord, ResponseRecord


def test_matching_handles_duplicate_txid_safely() -> None:
    q1 = QueryRecord(1.0, 100, "example.com", 1, "udp", "1.1.1.1", 1234, "8.8.8.8", 53)
    q2 = QueryRecord(2.0, 100, "example.com", 1, "udp", "1.1.1.1", 1234, "8.8.8.8", 53)
    r1 = ResponseRecord(1.5, 100, "example.com", 1, "udp", "8.8.8.8", 53, "1.1.1.1", 1234)

    matched, unmatched, late, duplicates = match_dns_queries(
        [q1, q2], [r1], late_threshold_seconds=1.0
    )

    assert len(matched) == 1
    assert matched[0].query.sent_at == 1.0
    assert len(unmatched) == 1
    assert late == 0
    assert duplicates == 0
