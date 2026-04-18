from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from scapy.packet import Packet

from dns_latency_probe.analysis import LatencyStats, compute_latency_stats
from dns_latency_probe.capture import extract_dns_records, start_capture, stop_capture
from dns_latency_probe.config import ProbeConfig
from dns_latency_probe.domains import load_domains
from dns_latency_probe.matching import match_dns_queries
from dns_latency_probe.models import MatchedPair, QueryRecord
from dns_latency_probe.plotting import plot_latency_histogram, plot_latency_timeseries
from dns_latency_probe.query_worker import run_query_loop
from dns_latency_probe.reporting import write_json_summary, write_markdown_report, write_pdf_report

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class RunArtifacts:
    pcap_path: Path
    json_path: Path
    markdown_path: Path
    pdf_path: Path
    histogram_path: Path
    timeseries_path: Path
    stats: LatencyStats


@dataclass(slots=True)
class ArtifactPaths:
    pcap_path: Path
    json_path: Path
    markdown_path: Path
    pdf_path: Path
    histogram_path: Path
    timeseries_path: Path


def _build_filename_prefix(timestamp_prefix: str, output_base_name: str) -> str:
    if output_base_name:
        return f"{timestamp_prefix}_{output_base_name}"
    return timestamp_prefix


def _prefixed_filename(prefix: str, filename: str) -> str:
    return f"{prefix}_{filename}"


def _wait_for_probe_duration(
    *,
    duration_seconds: float,
    stop_event: threading.Event,
    worker: threading.Thread,
) -> None:
    deadline = time.monotonic() + duration_seconds
    while not stop_event.is_set() and worker.is_alive():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        stop_event.wait(timeout=min(remaining, 0.1))


def _build_artifact_paths(config: ProbeConfig, filename_prefix: str) -> ArtifactPaths:
    return ArtifactPaths(
        pcap_path=config.output_dir / _prefixed_filename(filename_prefix, config.pcap_file),
        json_path=config.output_dir / _prefixed_filename(filename_prefix, "summary.json"),
        markdown_path=config.output_dir / _prefixed_filename(filename_prefix, "report.md"),
        pdf_path=config.output_dir / _prefixed_filename(filename_prefix, "report.pdf"),
        histogram_path=config.output_dir
        / _prefixed_filename(filename_prefix, "latency_histogram.png"),
        timeseries_path=config.output_dir
        / _prefixed_filename(filename_prefix, "latency_timeseries.png"),
    )


def _run_capture_phase(
    *,
    config: ProbeConfig,
    domains: list[str],
    pcap_path: Path,
) -> tuple[list[Packet], list[QueryRecord]]:
    sent_queries: list[QueryRecord] = []
    capture_session = start_capture(config.interface)
    stop_event = threading.Event()
    expected_queries = max(int(config.rate * config.duration), 1)
    worker = threading.Thread(
        target=run_query_loop,
        kwargs={
            "domains": domains,
            "resolver": config.resolver,
            "resolver_port": config.resolver_port,
            "rate": config.rate,
            "stop_event": stop_event,
            "sent_queries": sent_queries,
            "expected_queries": expected_queries,
        },
        daemon=True,
        name="dns-query-worker",
    )

    packets = []
    worker_started = False
    try:
        LOGGER.info("Starting DNS query worker")
        worker.start()
        worker_started = True
        _wait_for_probe_duration(
            duration_seconds=config.duration,
            stop_event=stop_event,
            worker=worker,
        )
    finally:
        stop_event.set()
        if worker_started:
            worker.join(timeout=5)
        packets = stop_capture(capture_session, pcap_path)

    return packets, sent_queries


def _emit_reports(
    *,
    config: ProbeConfig,
    paths: ArtifactPaths,
    stats: LatencyStats,
    capture_queries: list[QueryRecord],
    latencies: list[float],
    matched: list[MatchedPair],
    run_date: str,
) -> None:
    src_ips = sorted({query.src_ip for query in capture_queries if query.src_ip is not None})
    sender_source_ip = ",".join(src_ips) if src_ips else "unknown"
    invocation_options: dict[str, object] = {
        "interface": config.interface,
        "domains_file": str(config.domains_file),
        "resolver": config.resolver,
        "resolver_port": config.resolver_port,
        "rate": config.rate,
        "duration": config.duration,
        "output_dir": str(config.output_dir),
        "output_base_name": config.output_base_name,
        "pcap_file": config.pcap_file,
        "log_level": config.log_level,
        "source_ips": src_ips,
    }

    write_json_summary(stats, invocation_options, paths.json_path)
    write_markdown_report(
        stats,
        paths.markdown_path,
        pcap_file=paths.pcap_path.name,
        histogram_file=paths.histogram_path.name,
        timeseries_file=paths.timeseries_path.name,
        pdf_file=paths.pdf_path.name,
        sender_source_ip=sender_source_ip,
    )
    plot_latency_histogram(
        latencies,
        paths.histogram_path,
        config.resolver,
        config.duration,
        sender_source_ip,
        run_date,
    )
    plot_latency_timeseries(
        matched,
        paths.timeseries_path,
        config.resolver,
        config.duration,
        sender_source_ip,
        run_date,
    )
    write_pdf_report(
        markdown_path=paths.markdown_path,
        histogram_path=paths.histogram_path,
        timeseries_path=paths.timeseries_path,
        output_path=paths.pdf_path,
    )


def run_probe(config: ProbeConfig) -> RunArtifacts:
    config.validate()
    config.output_dir.mkdir(parents=True, exist_ok=True)
    run_started_at = datetime.now()
    timestamp_prefix = run_started_at.strftime("%Y-%m-%d-%H-%M")
    run_date = run_started_at.strftime("%Y-%m-%d")
    filename_prefix = _build_filename_prefix(timestamp_prefix, config.output_base_name)
    paths = _build_artifact_paths(config, filename_prefix)

    domains = load_domains(config.domains_file)
    packets, sent_queries = _run_capture_phase(
        config=config,
        domains=domains,
        pcap_path=paths.pcap_path,
    )

    capture_queries, capture_responses = extract_dns_records(packets)

    matched, unmatched, late_count, duplicates, out_of_order, stale = match_dns_queries(
        capture_queries, capture_responses
    )
    latencies = [entry.latency_seconds for entry in matched]
    stats = compute_latency_stats(
        latencies=latencies,
        total_queries_sent=len(sent_queries),
        unmatched_queries=len(unmatched),
        late_responses=late_count,
        duplicate_response_candidates=duplicates,
        out_of_order_responses=out_of_order,
        stale_responses=stale,
    )

    _emit_reports(
        config=config,
        paths=paths,
        stats=stats,
        capture_queries=capture_queries,
        latencies=latencies,
        matched=matched,
        run_date=run_date,
    )

    return RunArtifacts(
        pcap_path=paths.pcap_path,
        json_path=paths.json_path,
        markdown_path=paths.markdown_path,
        pdf_path=paths.pdf_path,
        histogram_path=paths.histogram_path,
        timeseries_path=paths.timeseries_path,
        stats=stats,
    )
