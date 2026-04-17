# dns-latency-probe

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
  - PDF report (Markdown content + both charts)
  - Histogram PNG
  - Time-series PNG

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
```

## Privilege considerations

Live packet capture and raw packet sending on Linux often require elevated privileges (e.g., root or `CAP_NET_RAW`/`CAP_NET_ADMIN`).

In CI, tests avoid privileged sniffing by using synthetic packets and monkeypatched capture/send paths.

## Example usage

```bash
# from outside the repo:
git clone <YOUR_FORK_OR_REPO_URL> dns-response-time-monitor
cd dns-response-time-monitor

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .

# run with sudo for packet capture/raw packet privileges
sudo "$(pwd)/.venv/bin/dns-latency-probe" \
  --interface eth0 \
  --domains-file examples/domains.txt \
  --resolver 8.8.8.8 \
  --rate 20 \
  --duration 60 \
  --output-dir output \
  --output-base-name baseline-a \
  --pcap-file capture.pcap \
  --log-level INFO
```

## Output files

Given `--output-dir output`, generated files include timestamp-prefixed artifacts (format `YYYY-MM-DD-HH-MM_*`), and you can optionally include `--output-base-name` so files become `YYYY-MM-DD-HH-MM_<base-name>_*` for easy run comparison. The base name is normalized to a conservative slug (`lowercase letters`, `numbers`, and `-`).

Without `--output-base-name`:

- `output/2026-04-16-14-30_capture.pcap`
- `output/2026-04-16-14-30_summary.json`
- `output/2026-04-16-14-30_report.md`
- `output/2026-04-16-14-30_report.pdf`
- `output/2026-04-16-14-30_latency_histogram.png`
- `output/2026-04-16-14-30_latency_timeseries.png`

With `--output-base-name baseline-a`:

- `output/2026-04-16-14-30_baseline-a_capture.pcap`
- `output/2026-04-16-14-30_baseline-a_summary.json`
- `output/2026-04-16-14-30_baseline-a_report.md`

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
- More advanced outlier and jitter analytics.
- Optional Prometheus metrics exporter for long-running probes.
