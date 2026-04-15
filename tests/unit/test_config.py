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
