from pathlib import Path

import pytest

from dns_latency_probe.config import ProbeConfig


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
    with pytest.raises(ValueError, match="output-base-name"):
        config.validate()


def test_config_validation_rejects_separator_output_base_name(tmp_path: Path) -> None:
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    config = ProbeConfig(interface="lo", domains_file=domains_file, output_base_name="compare/run")
    with pytest.raises(ValueError, match="path separators"):
        config.validate()
