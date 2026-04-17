from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


OUTPUT_BASE_NAME_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def normalize_output_base_name(raw_output_base_name: str) -> str:
    stripped_output_base_name = raw_output_base_name.strip()
    if not stripped_output_base_name:
        return ""

    normalized_output_base_name = re.sub(r"[^a-z0-9]+", "-", stripped_output_base_name.lower())
    normalized_output_base_name = normalized_output_base_name.strip("-")
    normalized_output_base_name = re.sub(r"-{2,}", "-", normalized_output_base_name)
    return normalized_output_base_name


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
    pcap_file: str = "capture.pcap"
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        normalized_output_base_name = normalize_output_base_name(self.output_base_name)
        object.__setattr__(self, "output_base_name", normalized_output_base_name)

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
        if self.output_base_name and not OUTPUT_BASE_NAME_SLUG_RE.fullmatch(self.output_base_name):
            raise ValueError(
                "output-base-name must normalize to a slug containing only lowercase letters, numbers, and hyphens"
            )
        if not self.pcap_file.endswith(".pcap"):
            raise ValueError("pcap-file must end with .pcap")

    @property
    def pcap_path(self) -> Path:
        return self.output_dir / self.pcap_file
