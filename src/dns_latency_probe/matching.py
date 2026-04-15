from __future__ import annotations

from collections import defaultdict, deque

from dns_latency_probe.models import MatchedPair, QueryRecord, ResponseRecord


def _query_key(query: QueryRecord) -> tuple[int, str, int, str, str, int, str, int]:
    return (
        query.txid,
        query.qname,
        query.qtype,
        query.protocol,
        query.src_ip,
        query.src_port,
        query.dst_ip,
        query.dst_port,
    )


def _response_to_query_key(
    response: ResponseRecord,
) -> tuple[int, str, int, str, str, int, str, int]:
    return (
        response.txid,
        response.qname,
        response.qtype,
        response.protocol,
        response.dst_ip,
        response.dst_port,
        response.src_ip,
        response.src_port,
    )


def match_dns_queries(
    queries: list[QueryRecord], responses: list[ResponseRecord], late_threshold_seconds: float = 1.0
) -> tuple[list[MatchedPair], list[QueryRecord], int, int]:
    pending: dict[tuple[int, str, int, str, str, int, str, int], deque[QueryRecord]] = defaultdict(
        deque
    )

    for query in sorted(queries, key=lambda x: x.sent_at):
        pending[_query_key(query)].append(query)

    matched: list[MatchedPair] = []
    duplicates = 0
    late = 0

    for response in sorted(responses, key=lambda x: x.seen_at):
        key = _response_to_query_key(response)
        queue = pending.get(key)
        if not queue:
            continue

        candidate: QueryRecord | None = None
        while queue:
            q = queue.popleft()
            if response.seen_at >= q.sent_at:
                candidate = q
                break
            duplicates += 1

        if candidate is None:
            continue

        latency = response.seen_at - candidate.sent_at
        if latency > late_threshold_seconds:
            late += 1
        matched.append(MatchedPair(query=candidate, response=response, latency_seconds=latency))

    unmatched = [query for queue in pending.values() for query in queue]
    return matched, unmatched, late, duplicates
