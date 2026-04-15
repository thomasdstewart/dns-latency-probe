from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dns_latency_probe.app import run_probe
from dns_latency_probe.config import ProbeConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure DNS latency by sending DNS A queries with Scapy"
    )
    parser.add_argument("--interface", required=True, help="Network interface for packet capture")
    parser.add_argument(
        "--domains-file", required=True, type=Path, help="UTF-8 text file with domains"
    )
    parser.add_argument(
        "--resolver", default="127.0.0.1", help="DNS resolver IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--resolver-port", default=53, type=int, help="DNS resolver port (default: 53)"
    )
    parser.add_argument("--rate", default=10.0, type=float, help="Queries per second")
    parser.add_argument("--duration", default=3600.0, type=float, help="Run duration in seconds")
    parser.add_argument("--output-dir", default=Path("output"), type=Path, help="Output directory")
    parser.add_argument("--pcap-file", default="capture.pcap", help="PCAP filename")
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

    config = ProbeConfig(
        interface=args.interface,
        domains_file=args.domains_file,
        resolver=args.resolver,
        resolver_port=args.resolver_port,
        rate=args.rate,
        duration=args.duration,
        output_dir=args.output_dir,
        pcap_file=args.pcap_file,
        log_level=args.log_level,
    )

    try:
        artifacts = run_probe(config)
    except Exception as exc:
        logging.getLogger(__name__).error("Probe failed: %s", exc)
        return 1

    logging.getLogger(__name__).info(
        "Probe completed. Report=%s JSON=%s", artifacts.markdown_path, artifacts.json_path
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
