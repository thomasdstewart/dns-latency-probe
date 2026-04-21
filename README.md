# DNS Latency Probe

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
pip install -c constraints.txt -e .[dev]
```


For reproducible installs across local and CI environments, this repository ships a pinned `constraints.txt` file.
Apply it to every install command with `-c constraints.txt`.

## Container build and run (Podman on RHEL 8)

Build the container image from the repository root:

```bash
podman build -t dns-latency-probe:latest .
```

Run the probe with host networking and the capabilities needed for raw packet send/capture.
This example mounts `examples/` read-only for domains input and writes artifacts to `./output` on the host:

```bash
mkdir -p output

podman run --rm \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -v "$(pwd)/examples:/app/examples:ro,Z" \
  -v "$(pwd)/output:/app/output:Z" \
  dns-latency-probe:latest \
  --interface eth0 \
  --domains-file /app/examples/domains.txt \
  --resolver 8.8.8.8 \
  --rate 20 \
  --duration 60 \
  --output-dir /app/output \
  --output-base-name baseline-a \
  --output-format reports \
  --pcap-file /app/output/capture.pcap \
  --log-level INFO
```

Notes:

- Replace `eth0` with the correct host interface for your system.
- If SELinux is enforcing, the `:Z` volume suffix labels bind mounts for container access.
- You may need to run Podman with elevated privileges depending on your environment and capture policy.

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
pip install -c constraints.txt -e .

# run with sudo for packet capture/raw packet privileges
sudo "$(pwd)/.venv/bin/dns-latency-probe" \
  --interface eth0 \
  --domains-file examples/domains.txt \
  --resolver 8.8.8.8 \
  --rate 20 \
  --duration 60 \
  --output-dir output \
  --output-base-name baseline-a \
  --output-format reports \
  --pcap-file capture.pcap \
  --log-level INFO
```

## Output files

Given `--output-dir output`, generated report files include timestamp + resolver-prefixed artifacts (format `YYYY-MM-DD-HH-MM_<resolver-slug>_*`), and you can optionally include `--output-base-name` so files become `YYYY-MM-DD-HH-MM_<resolver-slug>_<base-name>_*` for easy run comparison. The base name is normalized to a conservative slug (`lowercase letters`, `numbers`, and `-`).

Without `--output-base-name`:

- `output/2026-04-16-14-30_8-8-8-8_capture.pcap`
- `output/2026-04-16-14-30_8-8-8-8_summary.json`
- `output/2026-04-16-14-30_8-8-8-8_report.md`
- `output/2026-04-16-14-30_8-8-8-8_report.pdf`
- `output/2026-04-16-14-30_8-8-8-8_latency_histogram.png`
- `output/2026-04-16-14-30_8-8-8-8_latency_timeseries.png`

With `--output-base-name baseline-a`:

- `output/2026-04-16-14-30_8-8-8-8_baseline-a_capture.pcap`
- `output/2026-04-16-14-30_8-8-8-8_baseline-a_summary.json`
- `output/2026-04-16-14-30_8-8-8-8_baseline-a_report.md`

## Prometheus textfile output

Use `--output-format prometheus` to write only a textfile collector `.prom` artifact (no JSON/Markdown/PDF/PNG/PCAP files):

```bash
sudo "$(pwd)/.venv/bin/dns-latency-probe" \
  --interface eth0 \
  --domains-file examples/domains.txt \
  --resolver 8.8.8.8 \
  --duration 60 \
  --output-format prometheus \
  --prometheus-dir /var/lib/node_exporter/textfile_collector
```

The `.prom` file is written atomically (`*.tmp` then rename) for safe cron usage.
In prometheus mode, filenames are stable per probe (`<resolver-slug>[_<base-name>].prom`) so each run replaces the same file.

## Testing

```bash
ruff check .
black --check .
mypy
pytest
# optional coverage when pytest-cov is installed
pytest --cov=src/dns_latency_probe --cov-report=term-missing
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
