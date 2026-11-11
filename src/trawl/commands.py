"""Argv builders. Lists, never a shell string."""

from pathlib import Path
from urllib.parse import urlparse, urlunparse

from trawl.config import Config
from trawl.models import Host


def nmap_argv(target: str, cfg: Config, xml_path: Path) -> list[str]:
    opts = cfg.nmap
    argv = ["nmap"]
    if opts.skip_ping:
        argv.append("-Pn")
    if opts.service_detection:
        argv.append("-sV")
    if opts.scripts:
        argv.append("-sC")
    argv.extend(["--top-ports", str(opts.top_ports), f"-{opts.timing}", "-oX", str(xml_path)])
    argv.extend(opts.extra)
    argv.append(target)
    return argv


def ffuf_argv(base: str, cfg: Config, out_path: Path) -> list[str]:
    opts = cfg.ffuf
    argv = [
        "ffuf",
        "-u",
        _fuzz_url(base),
        "-w",
        opts.wordlist,
        "-t",
        str(opts.threads),
        "-of",
        "json",
        "-o",
        str(out_path),
        "-noninteractive",
    ]
    if opts.match_codes:
        argv.extend(["-mc", opts.match_codes])
    if opts.filter_codes:
        argv.extend(["-fc", ",".join(str(code) for code in opts.filter_codes)])
    if opts.extensions:
        argv.extend(["-e", ",".join(f".{ext}" for ext in opts.extensions)])
    if opts.rate > 0:
        argv.extend(["-rate", str(opts.rate)])
    return argv


def nuclei_argv(base: str, cfg: Config, out_path: Path) -> list[str]:
    opts = cfg.nuclei
    argv = [
        "nuclei",
        "-target",
        base,
        "-jsonl",
        "-output",
        str(out_path),
        "-silent",
        "-no-color",
        "-disable-update-check",
    ]
    if opts.severity:
        argv.extend(["-severity", ",".join(opts.severity)])
    if opts.rate_limit > 0:
        argv.extend(["-rate-limit", str(opts.rate_limit)])
    for template in opts.templates:
        argv.extend(["-t", template])
    return argv


def http_urls_from_hosts(hosts: list[Host]) -> list[str]:
    urls: list[str] = []
    for host in hosts:
        name = host.label
        for port in host.ports:
            if not port.is_open or not port.is_http:
                continue
            urls.append(_origin(port.scheme, name, port.port))
    return urls


def urls_for_assumed_ports(host: str, ports: list[int]) -> list[str]:
    urls: list[str] = []
    for port in ports:
        scheme = "https" if port in {443, 8443, 4443} else "http"
        urls.append(_origin(scheme, host, port))
    return urls


def _origin(scheme: str, host: str, port: int) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _fuzz_url(base: str) -> str:
    parsed = urlparse(base)
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunparse(parsed._replace(path=f"{path}FUZZ", query="", fragment=""))
