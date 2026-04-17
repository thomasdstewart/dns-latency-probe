from pathlib import Path
import socket

import pytest

from dns_latency_probe.config import ProbeConfig, normalize_output_base_name


def test_config_validation_success(tmp_path: Path) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    config = ProbeConfig(interface="lo", domains_file=domains_file)
    config.validate()


def test_config_validation_bad_rate(tmp_path: Path) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    config = ProbeConfig(interface="lo", domains_file=domains_file, rate=0)
    with pytest.raises(ValueError, match="rate"):
        config.validate()


def test_config_validation_rejects_blank_output_base_name(tmp_path: Path) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    config = ProbeConfig(interface="lo", domains_file=domains_file, output_base_name="   ")
    config.validate()
    assert config.output_base_name == ""


def test_config_validation_normalizes_separator_output_base_name(tmp_path: Path) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    config = ProbeConfig(interface="lo", domains_file=domains_file, output_base_name="compare/run")
    config.validate()
    assert config.output_base_name == "compare-run"


def test_normalize_output_base_name_uses_conservative_slug() -> None:
    assert normalize_output_base_name("  Baseline A @ Night #1 ") == "baseline-a-night-1"


def test_config_validation_accepts_hostname_resolver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    def fake_getaddrinfo(*_: object, **__: object) -> list[object]:
        return [object()]

    monkeypatch.setattr("dns_latency_probe.config.socket.getaddrinfo", fake_getaddrinfo)
    config = ProbeConfig(interface="lo", domains_file=domains_file, resolver="dns.google")
    config.validate()


def test_config_validation_rejects_invalid_resolver_hostname(tmp_path: Path) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    config = ProbeConfig(interface="lo", domains_file=domains_file, resolver="bad host")
    with pytest.raises(ValueError, match="IPv4/IPv6 address or DNS hostname"):
        config.validate()


def test_config_validation_rejects_unresolvable_resolver_hostname(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    def fake_getaddrinfo(*_: object, **__: object) -> list[object]:
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr("dns_latency_probe.config.socket.getaddrinfo", fake_getaddrinfo)
    config = ProbeConfig(interface="lo", domains_file=domains_file, resolver="resolver.invalid")
    with pytest.raises(ValueError, match="could not be resolved"):
        config.validate()
