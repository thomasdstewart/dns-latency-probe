from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class QueryRecord:
    sent_at: float
    txid: int
    qname: str
    qtype: int
    protocol: str
    src_ip: Optional[str]
    src_port: int
    dst_ip: str
    dst_port: int


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class MatchedPair:
    query: QueryRecord
    response: ResponseRecord
    latency_seconds: float
