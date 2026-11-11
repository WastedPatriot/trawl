"""What you're allowed to type as a target, and how to take it apart."""

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from trawl.errors import TrawlError

_HOST = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)


def load_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TrawlError(f"couldn't read {path}: {exc.strerror}") from exc
    items: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            items.append(line)
    return items


def normalise_targets(raw: list[str]) -> list[str]:
    if not raw:
        raise TrawlError("give me a target, or a file of them with -t")
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in raw:
        target = validate_target(item)
        if target not in seen:
            seen.add(target)
            cleaned.append(target)
    return cleaned


def validate_target(target: str) -> str:
    target = target.strip().rstrip(".")
    if not target or target.startswith("-") or any(ch.isspace() for ch in target):
        raise TrawlError(f"that doesn't look like a host or url: {target!r}")
    if "://" in target:
        return _validate_url(target)
    if _looks_like_ip(target):
        _parse_ip_or_net(target)
        return target
    if _HOST.fullmatch(target):
        return target
    raise TrawlError(f"that doesn't look like a host or url: {target}")


def host_of(target: str) -> str:
    if "://" in target:
        hostname = urlparse(target).hostname
        return hostname or target
    return target


def is_url(target: str) -> bool:
    return "://" in target


def is_network(target: str) -> bool:
    return "://" not in target and "/" in target


def base_url(target: str) -> str | None:
    """A URL target is already a web base. Hosts are not, until nmap says so."""
    if not is_url(target):
        return None
    return target.rstrip("/")


def _validate_url(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TrawlError(f"only http(s) urls, and they need a host: {target}")
    if parsed.username or parsed.password:
        raise TrawlError("drop the username from the url")
    if parsed.query or parsed.fragment:
        raise TrawlError("no query string or fragment in a target")
    if parsed.hostname and _looks_like_ip(parsed.hostname):
        _parse_ip_or_net(parsed.hostname)
    elif parsed.hostname and not _HOST.fullmatch(parsed.hostname):
        raise TrawlError(f"that doesn't look like a host or url: {target}")
    return target.rstrip("/")


def _looks_like_ip(value: str) -> bool:
    head = value.split("/", 1)[0]
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", head))


def _parse_ip_or_net(value: str) -> ipaddress.IPv4Address | ipaddress.IPv4Network:
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise TrawlError(f"bad address: {value}") from exc
