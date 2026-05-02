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
from dns_latency_probe.config import ProbeConfig, normalize_output_base_name
from dns_latency_probe.domains import load_domains
from dns_latency_probe.matching import match_dns_queries
from dns_latency_probe.models import MatchedPair, QueryRecord
from dns_latency_probe.plotting import plot_latency_histogram, plot_latency_run_comparison, plot_latency_timeseries
from dns_latency_probe.prometheus import write_prometheus_textfile
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
    prometheus_path: Path
    stats: LatencyStats


@dataclass(slots=True)
class ArtifactPaths:
    pcap_path: Path
    json_path: Path
    markdown_path: Path
    pdf_path: Path
    histogram_path: Path
    timeseries_path: Path
    prometheus_path: Path


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


def _build_artifact_paths(
    config: ProbeConfig, *, timestamp_prefix: str, output_base_name: str
) -> ArtifactPaths:
    resolver_slug = normalize_output_base_name(config.resolver) or "resolver"
    report_prefix_parts = [timestamp_prefix, resolver_slug]
    metrics_prefix_parts = [resolver_slug]
    if output_base_name:
        report_prefix_parts.append(output_base_name)
        metrics_prefix_parts.append(output_base_name)
    filename_prefix = "_".join(report_prefix_parts)
    prometheus_prefix = "_".join(metrics_prefix_parts)
    return ArtifactPaths(
        pcap_path=config.output_dir / f"{filename_prefix}_{config.pcap_file}",
        json_path=config.output_dir / f"{filename_prefix}_summary.json",
        markdown_path=config.output_dir / f"{filename_prefix}_report.md",
        pdf_path=config.output_dir / f"{filename_prefix}_report.pdf",
        histogram_path=config.output_dir / f"{filename_prefix}_latency_histogram.png",
        timeseries_path=config.output_dir / f"{filename_prefix}_latency_timeseries.png",
        prometheus_path=config.prometheus_dir / f"{prometheus_prefix}.prom",
    )


def _run_capture_phase(
    *,
    config: ProbeConfig,
    domains: list[str],
    pcap_path: Path | None,
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
        packets = stop_capture(capture_session, pcap_path=pcap_path)

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

    write_json_summary(stats, invocation_options, paths.json_path, latencies_seconds=latencies)
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


def _emit_prometheus_metrics(
    *,
    config: ProbeConfig,
    paths: ArtifactPaths,
    stats: LatencyStats,
    run_started_at: datetime,
) -> None:
    write_prometheus_textfile(
        output_path=paths.prometheus_path,
        stats=stats,
        resolver=config.resolver,
        resolver_port=config.resolver_port,
        output_base_name=config.output_base_name,
        run_started_unix=int(run_started_at.timestamp()),
    )


def run_probe(config: ProbeConfig) -> RunArtifacts:
    config.validate()
    config.output_dir.mkdir(parents=True, exist_ok=True)
    run_started_at = datetime.now()
    timestamp_prefix = run_started_at.strftime("%Y-%m-%d-%H-%M")
    run_date = run_started_at.strftime("%Y-%m-%d")
    paths = _build_artifact_paths(
        config,
        timestamp_prefix=timestamp_prefix,
        output_base_name=config.output_base_name,
    )

    domains = load_domains(config.domains_file)
    packets, sent_queries = _run_capture_phase(
        config=config,
        domains=domains,
        pcap_path=paths.pcap_path if config.output_format == "reports" else None,
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

    if config.output_format == "reports":
        _emit_reports(
            config=config,
            paths=paths,
            stats=stats,
            capture_queries=capture_queries,
            latencies=latencies,
            matched=matched,
            run_date=run_date,
        )
    else:
        _emit_prometheus_metrics(
            config=config,
            paths=paths,
            stats=stats,
            run_started_at=run_started_at,
        )

    return RunArtifacts(
        pcap_path=paths.pcap_path,
        json_path=paths.json_path,
        markdown_path=paths.markdown_path,
        pdf_path=paths.pdf_path,
        histogram_path=paths.histogram_path,
        timeseries_path=paths.timeseries_path,
        prometheus_path=paths.prometheus_path,
        stats=stats,
    )


def compare_runs_from_json(json_paths: list[Path], output_dir: Path) -> Path:
    import json

    run_latencies: list[list[float]] = []
    run_labels: list[str] = []
    for json_path in json_paths:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        latencies = payload.get("latencies_seconds")
        if not isinstance(latencies, list):
            raise ValueError(f"missing latencies_seconds in {json_path}")
        run_latencies.append([float(value) for value in latencies])
        run_labels.append(json_path.stem.replace("_summary", ""))

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "latency_run_comparison.png"
    plot_latency_run_comparison(run_latencies, run_labels, output_path)
    return output_path
