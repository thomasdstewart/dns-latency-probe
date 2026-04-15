from pathlib import Path

import pytest

from dns_latency_probe.domains import DomainFileError, load_domains


def test_load_domains_ignores_comments_and_blank_lines(tmp_path: Path) -> None:
    file_path = tmp_path / "domains.txt"
    file_path.write_text("\n# comment\nexample.com\n  \nexample.org\n", encoding="utf-8")

    assert load_domains(file_path) == ["example.com", "example.org"]


def test_load_domains_raises_for_empty_effective_file(tmp_path: Path) -> None:
    file_path = tmp_path / "domains.txt"
    file_path.write_text("\n# only comments\n", encoding="utf-8")

    with pytest.raises(DomainFileError):
        load_domains(file_path)
