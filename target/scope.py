from dataclasses import dataclass, field


@dataclass
class Target:
    original: str
    hostname: str | None = None
    ip: str | None = None
    dns: dict[str, list[str]] = field(
        default_factory=dict
    )
    http: dict = field(
        default_factory=dict
    )
    nmap: dict = field(
        default_factory=dict
    )
    vulnerabilities: list[dict] = field(
    default_factory=list
    )

    @property
    def scan_target(self) -> str:
        return self.hostname or self.original