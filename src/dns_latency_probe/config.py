from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from pathlib import Path

OUTPUT_BASE_NAME_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")


def normalize_output_base_name(raw_output_base_name: str) -> str:
    stripped_output_base_name = raw_output_base_name.strip()
    if not stripped_output_base_name:
        return ""

    normalized_output_base_name = re.sub(r"[^a-z0-9]+", "-", stripped_output_base_name.lower())
    normalized_output_base_name = normalized_output_base_name.strip("-")
    normalized_output_base_name = re.sub(r"-{2,}", "-", normalized_output_base_name)
    return normalized_output_base_name


def _is_valid_hostname(hostname: str) -> bool:
    stripped_hostname = hostname.strip()
    if not stripped_hostname or len(stripped_hostname) > 253:
        return False

    normalized_hostname = stripped_hostname.rstrip(".")
    if not normalized_hostname:
        return False

    labels = normalized_hostname.split(".")
    return all(
        HOSTNAME_LABEL_RE.fullmatch(label) is not None
        and not label.startswith("-")
        and not label.endswith("-")
        for label in labels
    )


def validate_resolver_target(resolver: str, resolver_port: int) -> None:
    stripped_resolver = resolver.strip()
    if not stripped_resolver:
        raise ValueError("resolver must be a non-empty IP address or hostname")

    try:
        parsed_ip = ipaddress.ip_address(stripped_resolver)
    except ValueError:
        pass
    else:
        if parsed_ip.version == 6:
            raise ValueError("resolver IPv6 addresses are not supported yet; use an IPv4 resolver")
        return

    if not _is_valid_hostname(stripped_resolver):
        raise ValueError("resolver must be a valid IPv4/IPv6 address or DNS hostname")

    try:
        ipv4_infos = socket.getaddrinfo(
            stripped_resolver,
            resolver_port,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            f"resolver hostname could not be resolved to an IPv4 address: {stripped_resolver}"
        ) from exc
    if not ipv4_infos:
        raise ValueError(
            f"resolver hostname did not return any IPv4 addresses: {stripped_resolver}"
        )


@dataclass(slots=True, frozen=True)
class ProbeConfig:
    interface: str
    domains_file: Path
    resolver: str = "127.0.0.1"
    resolver_port: int = 53
    rate: float = 10.0
    duration: float = 3600.0
    output_dir: Path = Path("output")
    output_base_name: str = ""
    output_format: str = "reports"
    prometheus_dir: Path = Path("metrics")
    pcap_file: str = "capture.pcap"
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        normalized_output_base_name = normalize_output_base_name(self.output_base_name)
        object.__setattr__(self, "output_base_name", normalized_output_base_name)
        object.__setattr__(self, "resolver", self.resolver.strip())
        object.__setattr__(self, "output_format", self.output_format.strip().lower())

    def validate(self) -> None:
        if not self.interface.strip():
            raise ValueError("interface must be a non-empty string")
        if not self.domains_file.exists():
            raise ValueError(f"domains file does not exist: {self.domains_file}")
        if self.rate <= 0:
            raise ValueError("rate must be > 0")
        if self.duration <= 0:
            raise ValueError("duration must be > 0")
        if self.resolver_port <= 0 or self.resolver_port > 65535:
            raise ValueError("resolver port must be in range 1..65535")
        validate_resolver_target(self.resolver, self.resolver_port)
        if self.output_base_name and not OUTPUT_BASE_NAME_SLUG_RE.fullmatch(self.output_base_name):
            raise ValueError(
                "output-base-name must normalize to a slug containing only lowercase "
                "letters, numbers, and hyphens"
            )
        if self.output_format not in {"reports", "prometheus"}:
            raise ValueError("output-format must be either 'reports' or 'prometheus'")
        if not self.pcap_file.endswith(".pcap"):
            raise ValueError("pcap-file must end with .pcap")

    @property
    def pcap_path(self) -> Path:
        return self.output_dir / self.pcap_file
