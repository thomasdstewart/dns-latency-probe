# Full Code Review (Intentionally Harsh)

## Findings and recommendations

- **Critical: race condition in packet capture buffer.** `start_capture()` appends to `packets` from a sniffer callback thread while `stop_capture()` can stop and immediately persist `session.packets` with no synchronization. Add a lock-protected queue/list or switch to Scapy storage semantics to avoid partial writes and data races.
- **Critical: no `try/finally` around runtime lifecycle.** `run_probe()` starts capture and worker threads and then performs many downstream steps, but any exception in the middle can leave capture/thread resources in undefined state. Wrap run lifecycle in `try/finally` so stop/join/cleanup always execute.
- **Major: duration timing is naïve and drifts.** The probe controls run time via `time.sleep(config.duration)` and only later asks thread shutdown. Use a monotonic deadline loop and cooperative stop checks to enforce duration accurately under load.
- **Major: source IP recording is knowingly wrong in sent query records.** Query worker hardcodes `src_ip="0.0.0.0"`, so sent metadata is not trustworthy and cannot be reconciled with capture truth when troubleshooting. Resolve source IP (or make it optional/None) instead of fabricating values.
- **Major: DNS parsing is brittle against modern Scapy DNS packet-list fields.** Code accesses `dns.qd.qtype` directly and helper logic assumes either `DNSQR` or indexable packet list; this is exactly where deprecation warnings are already appearing in tests. Update parsing to explicit first-element access (`qd[0]`) with robust type guards.
- **Major: matching duplicate counter is semantically wrong.** In matcher loop, responses observed before query send time are counted as "duplicates", but that condition actually indicates clock/order anomalies or stale packets. Separate metrics (`out_of_order`, `stale`) from true duplicate responses.
- **Major: exception handling in CLI is over-broad and hides diagnostics.** `main()` catches blanket `Exception` and prints one-line message. That destroys actionable traceback context for operator failures. Catch expected domain/config/runtime errors explicitly and log traceback for unexpected exceptions.
- **Major: resolver input validation is superficial.** Config validates resolver port but never validates resolver host/IP format or reachability assumptions. Validate with `ipaddress` (or explicitly support hostnames) and fail early with clear errors.
- **Medium: file naming safety is under-specified.** `output_base_name` rejects separators but allows arbitrary characters that are shell-hostile or awkward on filesystems. Add a conservative slug regex and normalize to safe token set.
- **Medium: reporting emits raw float values with inconsistent precision.** Markdown/JSON dump direct Python float repr values, making diffs noisy and reports harder to read. Apply stable formatting (e.g., 3-6 decimals) and include units consistently.
- **Medium: plotting hardcodes y-axis max of 10s.** Timeseries forcibly clips via `plt.ylim(0, 10)`, hiding exactly the pathological latencies operators care about. Derive bounds from data percentiles with headroom and annotate clipped points if needed.
- **Medium: tests acknowledge thread crash warning but do not fail.** Functional test emits `PytestUnhandledThreadExceptionWarning` from fake DNS server shutdown path, yet suite passes. Treat thread exceptions as test failures and fix shutdown handshake.
- **Medium: dependency and packaging posture is optimistic.** Project pins Python >=3.12 and heavy runtime deps but does not provide lockfile/constraints or reproducible env guidance; test command also assumes `pytest-cov` present via global `addopts`. Add a constraints file and make CI/test commands resilient without optional plugins.

## Priority order to fix

1. Lifecycle safety (`try/finally`, shutdown ordering, synchronization).
2. DNS parsing correctness + matching metric semantics.
3. Observability quality (truthful source metadata, richer CLI errors).
4. Report/plot ergonomics and test hygiene.
