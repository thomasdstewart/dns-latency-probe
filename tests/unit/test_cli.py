from pathlib import Path

from dns_latency_probe.cli import build_parser, main


def test_cli_parser_defaults() -> None:
    parser = build_parser()
    args = parser.parse_args(["--interface", "lo", "--domains-file", "domains.txt"])

    assert args.resolver == "127.0.0.1"
    assert args.duration == 3600.0


def test_cli_main_handles_runtime_error(tmp_path: Path) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    exit_code = main(
        [
            "--interface",
            "lo",
            "--domains-file",
            str(domains_file),
            "--duration",
            "0",
        ]
    )
    assert exit_code == 1
