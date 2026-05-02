from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dns_latency_probe.app import compare_runs_from_json, run_probe
from dns_latency_probe.config import ProbeConfig
from dns_latency_probe.domains import DomainFileError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure DNS latency by sending DNS A queries with Scapy"
    )
    parser.add_argument("--interface", help="Network interface for packet capture")
    parser.add_argument(
        "--domains-file", type=Path, help="UTF-8 text file with domains"
    )
    parser.add_argument(
        "--compare-json",
        nargs="+",
        type=Path,
        help="Read one or more summary JSON files and generate a comparison plot",
    )
    parser.add_argument(
        "--resolver",
        default="127.0.0.1",
        help="DNS resolver IPv4 address or hostname that resolves to IPv4 (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--resolver-port", default=53, type=int, help="DNS resolver port (default: 53)"
    )
    parser.add_argument("--rate", default=10.0, type=float, help="Queries per second")
    parser.add_argument("--duration", default=3600.0, type=float, help="Run duration in seconds")
    parser.add_argument("--output-dir", default=Path("output"), type=Path, help="Output directory")
    parser.add_argument(
        "--output-base-name",
        default="",
        help="Optional base name inserted after the timestamp in generated artifact filenames",
    )
    parser.add_argument("--pcap-file", default="capture.pcap", help="PCAP filename")
    parser.add_argument(
        "--output-format",
        default="reports",
        choices=["reports", "prometheus"],
        help="Output mode: full report artifacts or Prometheus textfile metrics",
    )
    parser.add_argument(
        "--prometheus-dir",
        default=Path("metrics"),
        type=Path,
        help="Directory for Prometheus textfile collector .prom artifacts",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    if args.compare_json:
        if len(args.compare_json) < 2:
            logger = logging.getLogger(__name__)
            logger.error("--compare-json requires at least two files")
            return 1
        output_path = compare_runs_from_json(args.compare_json, args.output_dir)
        logging.getLogger(__name__).info("Comparison plot=%s", output_path)
        return 0

    if not args.interface or not args.domains_file:
        logging.getLogger(__name__).error("--interface and --domains-file are required unless --compare-json is used")
        return 1

    config = ProbeConfig(
        interface=args.interface,
        domains_file=args.domains_file,
        resolver=args.resolver,
        resolver_port=args.resolver_port,
        rate=args.rate,
        duration=args.duration,
        output_dir=args.output_dir,
        output_base_name=args.output_base_name,
        pcap_file=args.pcap_file,
        output_format=args.output_format,
        prometheus_dir=args.prometheus_dir,
        log_level=args.log_level,
    )

    logger = logging.getLogger(__name__)

    try:
        artifacts = run_probe(config)
    except (DomainFileError, ValueError, OSError, RuntimeError) as exc:
        logger.error("Probe failed: %s", exc)
        return 1
    except Exception:
        logger.exception("Probe failed due to an unexpected error")
        return 1

    if config.output_format == "prometheus":
        logging.getLogger(__name__).info(
            "Probe completed. Prometheus=%s",
            artifacts.prometheus_path,
        )
    else:
        logging.getLogger(__name__).info(
            "Probe completed. Report=%s JSON=%s", artifacts.markdown_path, artifacts.json_path
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
