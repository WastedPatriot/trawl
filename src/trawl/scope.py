"""Scope is matched as written. No DNS, so a name can't sneak in through a CIDR."""

import ipaddress
from pathlib import Path

from trawl.errors import TrawlError
from trawl.targets import host_of, load_lines, validate_target


def load_scope(path: Path) -> list[str]:
    entries = load_lines(path)
    if not entries:
        raise TrawlError(f"scope file {path} is empty")
    for entry in entries:
        _check_entry(entry)
    return entries


def enforce_scope(targets: list[str], entries: list[str]) -> None:
    outside = [target for target in targets if not in_scope(target, entries)]
    if not outside:
        return
    listed = ", ".join(outside)
    raise TrawlError(f"outside scope: {listed}")


def in_scope(target: str, entries: list[str]) -> bool:
    host = host_of(target)
    for entry in entries:
        if _entry_covers(host, entry):
            return True
    return False


def _check_entry(entry: str) -> None:
    if "://" in entry:
        raise TrawlError(f"scope entries are hosts or ranges, not urls: {entry}")
    if entry.startswith("*."):
        rest = entry[2:].rstrip(".")
        if not rest or "/" in rest or ":" in rest:
            raise TrawlError(f"bad scope entry: {entry}")
        validate_target(rest)
        return
    validate_target(entry)


def _entry_covers(host: str, entry: str) -> bool:
    if entry.startswith("*.") or _is_name(entry):
        return _name_match(host, entry)
    # A hostname does not match an address entry. We don't resolve.
    if _is_name(host) and not _is_ip_literal(host):
        return False
    try:
        target_net = _as_network(host)
        entry_net = _as_network(entry)
    except ValueError:
        return False
    return target_net.subnet_of(entry_net)


def _name_match(host: str, entry: str) -> bool:
    host_name = host.casefold().rstrip(".")
    pattern = entry.casefold().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host_name.endswith(suffix) and host_name != suffix.lstrip(".")
    return host_name == pattern


def _is_name(value: str) -> bool:
    if value.startswith("*."):
        return True
    if "/" in value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("/", 1)[0])
    except ValueError:
        return False
    return True


def _as_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if "/" in value:
        return ipaddress.ip_network(value, strict=False)
    return ipaddress.ip_network(f"{value}/32", strict=False)
