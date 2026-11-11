"""Plain results. Parsers fill these; the report just reads them."""

from dataclasses import dataclass, field

# Shown when a scan, or the whole run, comes back empty.
NOTHING = "nothing in the nets today"

_HTTP_BITS = ("http", "https")


@dataclass
class Port:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: list[tuple[str, str]] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def is_http(self) -> bool:
        blob = f"{self.service} {self.tunnel}".lower()
        return any(bit in blob for bit in _HTTP_BITS)

    @property
    def scheme(self) -> str:
        name = self.service.lower()
        if name.startswith("https") or self.tunnel.lower() == "ssl":
            return "https"
        return "http"

    @property
    def service_label(self) -> str:
        if self.is_http and self.scheme == "https":
            return "https"
        return self.service or self.protocol

    @property
    def version_label(self) -> str:
        parts = [self.product, self.version]
        label = " ".join(part for part in parts if part).strip()
        if self.extrainfo:
            label = f"{label} ({self.extrainfo})" if label else self.extrainfo
        return label


@dataclass
class Host:
    address: str
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"
    ports: list[Port] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.hostnames:
            return self.hostnames[0]
        return self.address or "unknown"


@dataclass
class WebHit:
    url: str
    status: int
    length: int
    words: int = 0
    lines: int = 0
    content_type: str = ""
    fuzz: str = ""


@dataclass
class Finding:
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class Skipped:
    tool: str
    reason: str


@dataclass
class ScanReport:
    targets: list[str]
    hosts: list[Host] = field(default_factory=list)
    web: list[WebHit] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)
    # Tools that actually started, or would have on a dry-run.
    ran: list[str] = field(default_factory=list)
    # Empty results per tool that did run: "ffuf" -> how many hits, etc.
    counts: dict[str, int] = field(default_factory=dict)

    def open_ports(self) -> list[tuple[Host, Port]]:
        rows: list[tuple[Host, Port]] = []
        for host in self.hosts:
            for port in host.ports:
                if port.is_open:
                    rows.append((host, port))
        return rows

    def nothing_caught(self) -> bool:
        return not self.open_ports() and not self.web and not self.findings
