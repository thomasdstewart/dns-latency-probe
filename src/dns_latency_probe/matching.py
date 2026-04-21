from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

from dns_latency_probe.models import MatchedPair, QueryRecord, ResponseRecord


def _query_key(
    query: QueryRecord,
) -> Tuple[int, str, int, str, Optional[str], int, str, int]:
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
) -> Tuple[int, str, int, str, Optional[str], int, str, int]:
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
    queries: List[QueryRecord], responses: List[ResponseRecord], late_threshold_seconds: float = 1.0
) -> Tuple[List[MatchedPair], List[QueryRecord], int, int, int, int]:
    pending: Dict[
        Tuple[int, str, int, str, Optional[str], int, str, int],
        deque[QueryRecord],
    ] = defaultdict(deque)

    for query in sorted(queries, key=lambda x: x.sent_at):
        pending[_query_key(query)].append(query)

    matched: List[MatchedPair] = []
    query_keys = set(pending.keys())
    last_matched_sent_at: Dict[Tuple[int, str, int, str, Optional[str], int, str, int], float] = {}
    duplicates = 0
    out_of_order = 0
    stale = 0
    late = 0

    for response in sorted(responses, key=lambda x: x.seen_at):
        key = _response_to_query_key(response)
        queue = pending.get(key)
        if not queue:
            if key in query_keys:
                duplicates += 1
            else:
                stale += 1
            continue

        if response.seen_at < queue[0].sent_at:
            if key in last_matched_sent_at and response.seen_at >= last_matched_sent_at[key]:
                duplicates += 1
            else:
                out_of_order += 1
            continue

        candidate = queue.popleft()
        last_matched_sent_at[key] = candidate.sent_at

        latency = response.seen_at - candidate.sent_at
        if latency > late_threshold_seconds:
            late += 1
        matched.append(MatchedPair(query=candidate, response=response, latency_seconds=latency))

    unmatched = [query for queue in pending.values() for query in queue]
    return matched, unmatched, late, duplicates, out_of_order, stale
