from __future__ import annotations

import csv
import io
import logging
import subprocess
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

from dns_latency_probe.models import MatchedPair, QueryRecord, ResponseRecord

LOGGER = logging.getLogger(__name__)

_TSHARK_FIELDS = (
    "frame.time_epoch",
    "dns.id",
    "dns.flags.response",
    "dns.qry.name",
    "dns.qry.type",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "tcp.srcport",
    "tcp.dstport",
    "dns.time",
)

_QUERY_MATCH_EPSILON_SECONDS = 0.000001


@dataclass(slots=True)
class TsharkDnsAnalysis:
    queries: list[QueryRecord]
    matched: list[MatchedPair]
    unmatched: list[QueryRecord]
    responses_without_tshark_latency: int
    malformed_rows: int


def _normalise_qname(value: str) -> str:
    return value.rstrip(".").lower()


def _parse_int(value: str) -> int:
    return int(value, 0)


def _parse_port(row: dict[str, str], protocol: str, direction: str) -> int:
    key = f"{protocol}.{direction}port"
    value = row.get(key, "")
    if not value:
        raise ValueError(f"missing {key}")
    return _parse_int(value)


def _protocol_from_row(row: dict[str, str]) -> str:
    if row.get("udp.srcport") or row.get("udp.dstport"):
        return "udp"
    if row.get("tcp.srcport") or row.get("tcp.dstport"):
        return "tcp"
    raise ValueError("missing UDP/TCP ports")


def _query_key(query: QueryRecord) -> tuple[int, str, int, str, str | None, int, str, int]:
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
) -> tuple[int, str, int, str, str | None, int, str, int]:
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


def _query_from_row(row: dict[str, str]) -> QueryRecord:
    protocol = _protocol_from_row(row)
    return QueryRecord(
        sent_at=float(row["frame.time_epoch"]),
        txid=_parse_int(row["dns.id"]),
        qname=_normalise_qname(row["dns.qry.name"]),
        qtype=_parse_int(row["dns.qry.type"]),
        protocol=protocol,
        src_ip=row.get("ip.src") or None,
        src_port=_parse_port(row, protocol, "src"),
        dst_ip=row["ip.dst"],
        dst_port=_parse_port(row, protocol, "dst"),
    )


def _response_from_row(row: dict[str, str]) -> ResponseRecord:
    protocol = _protocol_from_row(row)
    return ResponseRecord(
        seen_at=float(row["frame.time_epoch"]),
        txid=_parse_int(row["dns.id"]),
        qname=_normalise_qname(row["dns.qry.name"]),
        qtype=_parse_int(row["dns.qry.type"]),
        protocol=protocol,
        src_ip=row["ip.src"],
        src_port=_parse_port(row, protocol, "src"),
        dst_ip=row["ip.dst"],
        dst_port=_parse_port(row, protocol, "dst"),
    )


def _synthetic_query_from_response(response: ResponseRecord, latency_seconds: float) -> QueryRecord:
    return QueryRecord(
        sent_at=response.seen_at - latency_seconds,
        txid=response.txid,
        qname=response.qname,
        qtype=response.qtype,
        protocol=response.protocol,
        src_ip=response.dst_ip,
        src_port=response.dst_port,
        dst_ip=response.src_ip,
        dst_port=response.src_port,
    )


def _pop_matching_query(
    pending: dict[tuple[int, str, int, str, str | None, int, str, int], deque[QueryRecord]],
    key: tuple[int, str, int, str, str | None, int, str, int],
    expected_sent_at: float,
) -> QueryRecord | None:
    queue = pending.get(key)
    if not queue:
        return None

    best_index = min(
        range(len(queue)),
        key=lambda index: abs(queue[index].sent_at - expected_sent_at),
    )
    if abs(queue[best_index].sent_at - expected_sent_at) > _QUERY_MATCH_EPSILON_SECONDS:
        return None

    queue.rotate(-best_index)
    query = queue.popleft()
    queue.rotate(best_index)
    if not queue:
        del pending[key]
    return query


def parse_tshark_dns_csv(csv_text: str) -> TsharkDnsAnalysis:
    reader = csv.DictReader(io.StringIO(csv_text))
    queries: list[QueryRecord] = []
    response_rows: list[tuple[ResponseRecord, float]] = []
    responses_without_tshark_latency = 0
    malformed_rows = 0

    for row in reader:
        try:
            response_flag = row.get("dns.flags.response", "").lower()
            is_response = response_flag in {"1", "true"}
            if is_response:
                latency_text = row.get("dns.time", "")
                if not latency_text:
                    responses_without_tshark_latency += 1
                    continue
                response_rows.append((_response_from_row(row), float(latency_text)))
            else:
                queries.append(_query_from_row(row))
        except (KeyError, ValueError):
            malformed_rows += 1

    pending: dict[tuple[int, str, int, str, str | None, int, str, int], deque[QueryRecord]] = (
        defaultdict(deque)
    )
    for captured_query in sorted(queries, key=lambda item: item.sent_at):
        pending[_query_key(captured_query)].append(captured_query)

    matched: list[MatchedPair] = []
    for response, latency_seconds in sorted(response_rows, key=lambda item: item[0].seen_at):
        expected_sent_at = response.seen_at - latency_seconds
        matched_query = _pop_matching_query(
            pending, _response_to_query_key(response), expected_sent_at
        )
        if matched_query is None:
            matched_query = _synthetic_query_from_response(response, latency_seconds)
        matched.append(
            MatchedPair(query=matched_query, response=response, latency_seconds=latency_seconds)
        )

    unmatched = [query for queue in pending.values() for query in queue]
    return TsharkDnsAnalysis(
        queries=queries,
        matched=matched,
        unmatched=unmatched,
        responses_without_tshark_latency=responses_without_tshark_latency,
        malformed_rows=malformed_rows,
    )


def analyse_pcap_with_tshark(pcap_path: Path) -> TsharkDnsAnalysis:
    command = [
        "tshark",
        "-n",
        "-r",
        str(pcap_path),
        "-Y",
        "dns",
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in _TSHARK_FIELDS:
        command.extend(("-e", field))

    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("tshark is required to analyse DNS packet captures") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        message = f"tshark failed while analysing {pcap_path}"
        if stderr:
            message = f"{message}: {stderr}"
        raise RuntimeError(message) from exc

    analysis = parse_tshark_dns_csv(completed.stdout)
    if analysis.malformed_rows:
        LOGGER.warning("Ignored %d malformed tshark CSV rows", analysis.malformed_rows)
    if analysis.responses_without_tshark_latency:
        LOGGER.info(
            "Ignored %d DNS responses without tshark dns.time values",
            analysis.responses_without_tshark_latency,
        )
    return analysis
