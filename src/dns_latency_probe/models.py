from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class QueryRecord:
    sent_at: float
    txid: int
    qname: str
    qtype: int
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


@dataclass(slots=True, frozen=True)
class ResponseRecord:
    seen_at: float
    txid: int
    qname: str
    qtype: int
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


@dataclass(slots=True, frozen=True)
class MatchedPair:
    query: QueryRecord
    response: ResponseRecord
    latency_seconds: float
