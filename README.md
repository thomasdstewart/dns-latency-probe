# DNS Latency Probe

`dns-latency-probe` is a CLI tool for measuring DNS response latency by:

1. Sending DNS A queries at a configurable rate.
2. Capturing DNS packets (UDP/TCP port 53).
3. Matching requests/responses.
4. Generating latency statistics and reports.

## Runtime model

This project is now **container-first** and documented for **Podman only**.

- Python runtime target: **3.14**
- Recommended execution path: build and run with Podman
- No backwards-compatibility guidance for older Python versions

## Build image

From the repository root:

```bash
podman build -t dns-latency-probe:latest .
```

## Run probe

The probe needs host networking and raw packet capabilities.
This example mounts `examples/` read-only for input and writes artifacts to `./output`.

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

- Replace `eth0` with the correct host interface.
- If SELinux is enforcing, `:Z` labels bind mounts for container access.
- Depending on your host policy, elevated privileges may still be required.

## Output files

For `--output-format reports`, output artifacts include:

- `.pcap`
- `_summary.json`
- `_report.md`
- `_report.pdf`
- `_latency_histogram.png`
- `_latency_timeseries.png`

Filenames include timestamp + resolver slug, and optionally `--output-base-name`.

## Prometheus textfile mode

Use `--output-format prometheus` to write only a `.prom` textfile collector artifact.

```bash
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
  --duration 60 \
  --output-format prometheus \
  --prometheus-dir /app/output
```
