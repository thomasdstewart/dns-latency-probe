from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from dns_latency_probe.analysis import LatencyStats, compute_latency_stats
from dns_latency_probe.capture import extract_dns_records, start_capture, stop_capture
from dns_latency_probe.config import ProbeConfig
from dns_latency_probe.domains import load_domains
from dns_latency_probe.matching import match_dns_queries
from dns_latency_probe.models import QueryRecord
from dns_latency_probe.plotting import plot_latency_histogram, plot_latency_timeseries
from dns_latency_probe.query_worker import run_query_loop
from dns_latency_probe.reporting import write_json_summary, write_markdown_report

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class RunArtifacts:
    pcap_path: Path
    json_path: Path
    markdown_path: Path
    histogram_path: Path
    timeseries_path: Path
    stats: LatencyStats


def run_probe(config: ProbeConfig) -> RunArtifacts:
    config.validate()
    config.output_dir.mkdir(parents=True, exist_ok=True)

    domains = load_domains(config.domains_file)
    sent_queries: list[QueryRecord] = []

    capture_session = start_capture(config.interface)
    stop_event = threading.Event()
    worker = threading.Thread(
        target=run_query_loop,
        kwargs={
            "domains": domains,
            "resolver": config.resolver,
            "resolver_port": config.resolver_port,
            "rate": config.rate,
            "stop_event": stop_event,
            "sent_queries": sent_queries,
        },
        daemon=True,
        name="dns-query-worker",
    )

    LOGGER.info("Starting DNS query worker")
    worker.start()
    time.sleep(config.duration)
    stop_event.set()
    worker.join(timeout=5)

    packets = stop_capture(capture_session, config.pcap_path)
    capture_queries, capture_responses = extract_dns_records(packets)

    matched, unmatched, late_count, duplicates = match_dns_queries(
        capture_queries, capture_responses
    )
    latencies = [entry.latency_seconds for entry in matched]
    stats = compute_latency_stats(
        latencies=latencies,
        total_queries_sent=len(sent_queries),
        unmatched_queries=len(unmatched),
        late_responses=late_count,
        duplicate_response_candidates=duplicates,
    )

    json_path = config.output_dir / "summary.json"
    markdown_path = config.output_dir / "report.md"
    histogram_path = config.output_dir / "latency_histogram.png"
    timeseries_path = config.output_dir / "latency_timeseries.png"

    write_json_summary(stats, json_path)
    write_markdown_report(
        stats,
        markdown_path,
        pcap_file=config.pcap_file,
        histogram_file=histogram_path.name,
        timeseries_file=timeseries_path.name,
    )
    plot_latency_histogram(latencies, histogram_path)
    plot_latency_timeseries(matched, timeseries_path)

    return RunArtifacts(
        pcap_path=config.pcap_path,
        json_path=json_path,
        markdown_path=markdown_path,
        histogram_path=histogram_path,
        timeseries_path=timeseries_path,
        stats=stats,
    )
