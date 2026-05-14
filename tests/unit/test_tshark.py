from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from dns_latency_probe.tshark import analyse_pcap_with_tshark, parse_tshark_dns_csv

CSV_HEADER = (
    '"frame.time_epoch","dns.id","dns.flags.response","dns.qry.name","dns.qry.type",'
    '"ip.src","ip.dst","udp.srcport","udp.dstport","tcp.srcport","tcp.dstport","dns.time"\n'
)


def test_parse_tshark_dns_csv_uses_dns_response_time_for_matched_pair() -> None:
    csv_text = CSV_HEADER + (
        '"10.000000","11","0","Example.COM","1","192.0.2.10","8.8.8.8",'
        '"55000","53","","",""\n'
        '"10.123456","11","1","Example.COM","1","8.8.8.8","192.0.2.10",'
        '"53","55000","","","0.123456"\n'
    )

    analysis = parse_tshark_dns_csv(csv_text)

    assert len(analysis.queries) == 1
    assert len(analysis.matched) == 1
    assert analysis.unmatched == []
    assert analysis.queries[0].qname == "example.com"
    assert analysis.matched[0].latency_seconds == pytest.approx(0.123456)
    assert analysis.matched[0].query is analysis.queries[0]
    assert analysis.matched[0].response.src_ip == "8.8.8.8"


def test_parse_tshark_dns_csv_tracks_unmatched_queries_and_responses_without_latency() -> None:
    csv_text = CSV_HEADER + (
        '"10.000000","11","0","example.com","1","192.0.2.10","8.8.8.8",'
        '"55000","53","","",""\n'
        '"11.000000","11","1","example.com","1","8.8.8.8","192.0.2.10",'
        '"53","55000","","",""\n'
    )

    analysis = parse_tshark_dns_csv(csv_text)

    assert len(analysis.unmatched) == 1
    assert analysis.responses_without_tshark_latency == 1
    assert analysis.matched == []


def test_parse_tshark_dns_csv_synthesises_query_when_query_row_is_missing() -> None:
    csv_text = CSV_HEADER + (
        '"10.250000","11","1","example.com","1","8.8.8.8","192.0.2.10",'
        '"53","55000","","","0.250000"\n'
    )

    analysis = parse_tshark_dns_csv(csv_text)

    assert len(analysis.queries) == 0
    assert len(analysis.matched) == 1
    assert analysis.matched[0].query.sent_at == pytest.approx(10.0)
    assert analysis.matched[0].query.src_ip == "192.0.2.10"
    assert analysis.matched[0].query.dst_ip == "8.8.8.8"


def test_analyse_pcap_with_tshark_runs_limited_csv_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pcap_path = tmp_path / "capture.pcap"
    csv_text = CSV_HEADER
    captured_command: list[str] = []

    def fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal captured_command
        captured_command = command
        assert check
        assert capture_output
        assert text
        return subprocess.CompletedProcess(command, 0, stdout=csv_text, stderr="")

    monkeypatch.setattr("dns_latency_probe.tshark.subprocess.run", fake_run)

    analyse_pcap_with_tshark(pcap_path)

    assert captured_command[:10] == [
        "tshark",
        "-n",
        "-r",
        str(pcap_path),
        "-Y",
        "dns",
        "-T",
        "fields",
        "-E",
        "header=y",
    ]
    assert "dns.time" in captured_command
    assert "-e" in captured_command


def test_analyse_pcap_with_tshark_reports_missing_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    monkeypatch.setattr("dns_latency_probe.tshark.subprocess.run", fake_run)

    with pytest.raises(RuntimeError, match="tshark is required"):
        analyse_pcap_with_tshark(tmp_path / "capture.pcap")
