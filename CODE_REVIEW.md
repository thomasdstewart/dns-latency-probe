# Full Code Review (Intentionally Harsh)

## Findings and recommendations

- **Medium: plotting still hard-clips latency at 10s with no visibility of clipped points.** You replaced linear scale with symlog, but `MAX_PLOT_LATENCY_SECONDS = 10.0` still truncates every outlier in both plots. That means severe latency spikes are silently flattened right when the chart should be loudest. Keep full values or explicitly annotate how many points were clipped and at what threshold.
- **Medium: `run_probe()` is still an oversized orchestrator that does everything.** Lifecycle, matching, stats, artifact naming, output path construction, report writing, and plotting all live in one function. This makes the “happy path” hard to reason about and painful to test in isolation. Split it into focused helpers (`_run_capture_phase`, `_build_artifact_paths`, `_emit_reports`) so failures are easier to localize and unit test.
- **Medium: duplicate filename-prefix helpers are needless indirection.** `_build_filename_prefix()` plus `_prefixed_filename()` creates extra hops for trivial string formatting. Collapse to one utility that returns all artifact names, or inline where used. Right now this is boilerplate noise.
- **Low: resolver validation does blocking DNS lookups during config validation.** `validate_resolver_target()` calls `socket.getaddrinfo()` synchronously. That can hang CLI startup under bad resolver/network conditions before any structured runtime logging begins. Consider optional “strict resolution” mode or a short timeout strategy so validation failures are fast and predictable.
- **Low: reporting and plotting APIs are argument-heavy and ripe for a context object.** Several calls repeat resolver/duration/source IP/date and artifact filenames as loose positional/keyword arguments. Introduce a small immutable report context dataclass to simplify signatures and reduce call-site churn when adding fields.

## Priority order to fix

1. Stop silently hiding latency outliers in plots.
2. Break up `run_probe()` into smaller, testable units.
3. Simplify filename/report plumbing and validation ergonomics.
