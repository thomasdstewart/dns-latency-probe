from pathlib import Path
from typing import List


class DomainFileError(ValueError):
    """Raised for invalid domain input files."""


def load_domains(domains_file: Path) -> List[str]:
    if not domains_file.exists():
        raise DomainFileError(f"domains file does not exist: {domains_file}")
    lines = domains_file.read_text(encoding="utf-8").splitlines()
    domains = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not domains:
        raise DomainFileError("domains file has no usable domain names")
    return domains
