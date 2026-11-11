"""Turn tool output into models. Quiet about junk, loud about broken XML."""

import json
import xml.etree.ElementTree as ET

from trawl.models import Finding, Host, Port, WebHit


def parse_nmap_xml(text: str) -> list[Host]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"nmap xml didn't parse: {exc}") from exc

    hosts: list[Host] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"

        address = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in {"ipv4", "ipv6"} and addr.get("addr"):
                address = addr.get("addr", "")
                break

        names: list[str] = []
        for hostname in host_el.findall("./hostnames/hostname"):
            name = (hostname.get("name") or "").strip()
            if name and name not in names:
                names.append(name)

        ports: list[Port] = []
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            # Closed and filtered rows are how nmap says "move on".
            if state != "open":
                continue
            portid = port_el.get("portid") or ""
            if not portid.isdigit():
                continue
            service = port_el.find("service")
            scripts: list[tuple[str, str]] = []
            for script in port_el.findall("script"):
                sid = (script.get("id") or "").strip()
                output = _one_line(script.get("output") or "")
                if sid and output:
                    scripts.append((sid, output))
            ports.append(
                Port(
                    port=int(portid),
                    protocol=port_el.get("protocol") or "tcp",
                    state=state,
                    service=_attr(service, "name"),
                    product=_attr(service, "product"),
                    version=_attr(service, "version"),
                    extrainfo=_attr(service, "extrainfo"),
                    tunnel=_attr(service, "tunnel"),
                    scripts=scripts,
                )
            )
        ports.sort(key=lambda item: (item.protocol, item.port))
        if address or names:
            hosts.append(
                Host(
                    address=address or names[0],
                    hostnames=names,
                    status=status,
                    ports=ports,
                )
            )
    return hosts


def parse_ffuf_json(text: str) -> list[WebHit]:
    if not text.strip():
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"ffuf json didn't parse: {exc}") from exc
    if not isinstance(data, dict):
        return []

    hits: list[WebHit] = []
    results = data.get("results") or []
    if not isinstance(results, list):
        return []
    for row in results:
        if not isinstance(row, dict):
            continue
        raw_input = row.get("input")
        fuzz = ""
        if isinstance(raw_input, dict) and raw_input:
            fuzz = str(next(iter(raw_input.values())))
        elif isinstance(raw_input, str):
            fuzz = raw_input
        hits.append(
            WebHit(
                url=str(row.get("url") or ""),
                status=_as_int(row.get("status")),
                length=_as_int(row.get("length")),
                words=_as_int(row.get("words")),
                lines=_as_int(row.get("lines")),
                content_type=str(row.get("content-type") or ""),
                fuzz=fuzz,
            )
        )
    hits.sort(key=lambda hit: (hit.status, hit.url))
    return hits


def parse_nuclei_jsonl(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        tags = _tags(info.get("tags"))
        template_id = str(row.get("template-id") or row.get("templateID") or "")
        findings.append(
            Finding(
                template_id=template_id,
                name=str(info.get("name") or template_id or "untitled"),
                severity=str(info.get("severity") or "unknown").lower(),
                host=str(row.get("host") or ""),
                matched_at=str(row.get("matched-at") or row.get("matched") or ""),
                description=_one_line(str(info.get("description") or "")),
                tags=tags,
            )
        )
    return findings


def _attr(element: ET.Element | None, key: str) -> str:
    if element is None:
        return ""
    return (element.get(key) or "").strip()


def _one_line(value: str, limit: int = 180) -> str:
    flat = " ".join(value.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 3] + "..."


def _as_int(value: object) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return 0


def _tags(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []
