# dns-response-time-monitor

`dns-latency-probe` is a production-minded CLI tool that measures DNS response latency by:

1. Sending DNS A queries with Scapy at a configurable rate.
2. Capturing DNS packets (UDP and TCP port 53) with Scapy.
3. Matching requests to responses in Python.
4. Computing latency statistics and generating reports/graphs.

## Features

- Python 3.12+
- Scapy for packet generation, sending, and capture
- Rate-controlled query loop over a domain list
- Coordinated stop event + threaded shutdown
- Robust request/response matching keyed by transaction + flow metadata
- Output artifacts:
  - `.pcap` capture
  - JSON summary
  - Markdown report
  - Histogram PNG
  - Time-series PNG

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
```

## Privilege considerations

Live packet capture and raw packet sending on Linux often require elevated privileges (e.g., root or `CAP_NET_RAW`/`CAP_NET_ADMIN`).

In CI, tests avoid privileged sniffing by using synthetic packets and monkeypatched capture/send paths.

## Example usage

```bash
dns-latency-probe \
  --interface lo \
  --domains-file examples/domains.txt \
  --resolver 127.0.0.1 \
  --rate 20 \
  --duration 60 \
  --output-dir output \
  --pcap-file capture.pcap \
  --log-level INFO
```

## Output files

Given `--output-dir output`, generated files include:

- `output/capture.pcap`
- `output/summary.json`
- `output/report.md`
- `output/latency_histogram.png`
- `output/latency_timeseries.png`

## Testing

```bash
ruff check .
black --check .
mypy
pytest
```

Tests include:

- Unit tests for parsing, config validation, rate limiter, matching, stats, and CLI handling.
- Functional tests for end-to-end execution with a fake local DNS server and graceful duration-based shutdown.

## How to run

1. Create/edit `examples/domains.txt` (one domain per line).
2. Ensure your resolver is reachable.
3. Run `dns-latency-probe` with your interface and desired options.
4. Inspect the JSON/Markdown/PNG outputs under your selected output directory.

## Future improvements

- Optional CSV export for per-query latencies.
- DNS-over-TCP query generation mode.
- More advanced outlier and jitter analytics.
- Optional Prometheus metrics exporter for long-running probes.
