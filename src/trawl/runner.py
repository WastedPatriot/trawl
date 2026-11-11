"""Run the three tools, or say which ones aren't on the boat."""

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from trawl.commands import (
    ffuf_argv,
    http_urls_from_hosts,
    nmap_argv,
    nuclei_argv,
    urls_for_assumed_ports,
)
from trawl.config import Config
from trawl.models import Finding, Host, ScanReport, Skipped, WebHit
from trawl.parse import parse_ffuf_json, parse_nmap_xml, parse_nuclei_jsonl
from trawl.targets import base_url, host_of, is_network

EventCallback = Callable[[str, dict], None]

_TOOLS = ("nmap", "ffuf", "nuclei")


def run_scan(
    targets: list[str],
    cfg: Config,
    *,
    dry_run: bool = False,
    skip: set[str] | None = None,
    http_ports: list[int] | None = None,
    callback: EventCallback | None = None,
) -> ScanReport:
    skipped_on_purpose = skip or set()
    report = ScanReport(targets=list(targets))
    out = Path(cfg.output_dir)
    paths = {name: shutil.which(name) for name in _TOOLS}
    http_ports = http_ports or []

    ffuf_block = _unavailable("ffuf", paths, skipped_on_purpose, cfg, dry_run, report)
    nuclei_block = _unavailable("nuclei", paths, skipped_on_purpose, cfg, dry_run, report)
    nmap_block = _unavailable("nmap", paths, skipped_on_purpose, cfg, dry_run, report)

    scanned: set[str] = set()
    seen_urls: set[str] = set()
    warned_unknown_http = False
    warned_network_ports = False

    for target in targets:
        host = host_of(target)
        bases: list[str] = []
        explicit = base_url(target)
        if explicit:
            bases.append(explicit)
        if http_ports and not is_network(target):
            bases.extend(urls_for_assumed_ports(host, http_ports))
        elif http_ports and is_network(target) and not warned_network_ports:
            warned_network_ports = True
            report.notes.append(
                "--http-ports is for single hosts. On a range, nmap has to find the web ports."
            )

        if nmap_block is None and host not in scanned:
            scanned.add(host)
            nmap_target = host
            xml_path = out / "nmap" / f"{_stem(nmap_target)}.xml"
            if not dry_run:
                xml_path.parent.mkdir(parents=True, exist_ok=True)
            argv = nmap_argv(nmap_target, cfg, xml_path)
            report.commands.append(argv)
            _ran(report, "nmap")
            if dry_run:
                _emit(callback, "plan", tool="nmap", target=nmap_target)
            else:
                _emit(callback, "start", tool="nmap", target=nmap_target)
                code, err = _execute(argv, cfg.timeout)
                hosts = []
                if xml_path.is_file():
                    hosts = _read_nmap(xml_path, nmap_target, report)
                    report.hosts.extend(hosts)
                    bases.extend(http_urls_from_hosts(hosts))
                open_count = sum(1 for item in hosts for port in item.ports if port.is_open)
                report.counts["nmap"] = report.counts.get("nmap", 0) + open_count
                if code != 0:
                    detail = err or f"nmap exited {code}"
                    report.notes.append(f"nmap on {nmap_target}: {detail[:300]}")
                if code != 0 and not xml_path.is_file():
                    report.notes.append(f"nmap produced no xml for {nmap_target}")
                _emit(
                    callback,
                    "done",
                    tool="nmap",
                    target=nmap_target,
                    count=open_count,
                    error=err if code != 0 else "",
                )

        if dry_run and not bases and nmap_block is None and not warned_unknown_http:
            warned_unknown_http = True
            report.notes.append(
                "ffuf and nuclei run per http service once nmap has been. "
                "Pass a URL or --http-ports to print those commands now."
            )

        for base in _dedupe(bases):
            if base in seen_urls:
                continue
            seen_urls.add(base)
            if ffuf_block is None:
                _run_ffuf(report, cfg, out, base, dry_run, callback)
            if nuclei_block is None:
                _run_nuclei(report, cfg, out, base, dry_run, callback)

    if (
        not seen_urls
        and not dry_run
        and (ffuf_block is None or nuclei_block is None)
        and "nmap" in report.ran
    ):
        report.notes.append("no http services, so the web tools sat this one out")

    return report


def _unavailable(
    tool: str,
    paths: dict[str, str | None],
    skip: set[str],
    cfg: Config,
    dry_run: bool,
    report: ScanReport,
) -> str | None:
    if tool in skip:
        reason = "skipped with --skip"
        report.skipped.append(Skipped(tool, reason))
        return reason

    missing = not paths.get(tool)
    if missing:
        # A real run skips it. Dry-run still prints the command, and says so.
        report.skipped.append(Skipped(tool, "not on PATH"))

    if tool == "ffuf" and not Path(cfg.ffuf.wordlist).is_file():
        if dry_run:
            report.notes.append(f"ffuf wordlist isn't there yet: {cfg.ffuf.wordlist}")
        elif not missing:
            reason = f"wordlist not found: {cfg.ffuf.wordlist}"
            report.skipped.append(Skipped(tool, reason))
            return reason

    if missing and not dry_run:
        return "not on PATH"
    return None


def _run_ffuf(
    report: ScanReport,
    cfg: Config,
    out: Path,
    base: str,
    dry_run: bool,
    callback: EventCallback | None,
) -> None:
    out_path = out / "ffuf" / f"{_stem(base)}.json"
    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    argv = ffuf_argv(base, cfg, out_path)
    report.commands.append(argv)
    _ran(report, "ffuf")
    if dry_run:
        _emit(callback, "plan", tool="ffuf", target=base)
        return
    _emit(callback, "start", tool="ffuf", target=base)
    code, err = _execute(argv, cfg.timeout)
    hits = []
    if out_path.is_file():
        try:
            hits = parse_ffuf_json(out_path.read_text(encoding="utf-8", errors="replace"))
        except ValueError as exc:
            report.notes.append(f"ffuf output for {base}: {exc}")
    added = _extend_web(report, hits)
    report.counts["ffuf"] = report.counts.get("ffuf", 0) + added
    if code != 0:
        report.notes.append(f"ffuf on {base}: {(err or f'exited {code}')[:300]}")
    _emit(
        callback,
        "done",
        tool="ffuf",
        target=base,
        count=len(hits),
        error=err if code != 0 else "",
    )


def _run_nuclei(
    report: ScanReport,
    cfg: Config,
    out: Path,
    base: str,
    dry_run: bool,
    callback: EventCallback | None,
) -> None:
    out_path = out / "nuclei" / f"{_stem(base)}.jsonl"
    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    argv = nuclei_argv(base, cfg, out_path)
    report.commands.append(argv)
    _ran(report, "nuclei")
    if dry_run:
        _emit(callback, "plan", tool="nuclei", target=base)
        return
    _emit(callback, "start", tool="nuclei", target=base)
    code, err = _execute(argv, cfg.timeout)
    found = []
    if out_path.is_file():
        found = parse_nuclei_jsonl(out_path.read_text(encoding="utf-8", errors="replace"))
        if cfg.nuclei.severity:
            allowed = set(cfg.nuclei.severity)
            found = [item for item in found if item.severity in allowed]
    added = _extend_findings(report, found)
    report.counts["nuclei"] = report.counts.get("nuclei", 0) + added
    if code != 0:
        report.notes.append(f"nuclei on {base}: {(err or f'exited {code}')[:300]}")
    _emit(
        callback,
        "done",
        tool="nuclei",
        target=base,
        count=len(found),
        error=err if code != 0 else "",
    )


def _extend_web(report: ScanReport, hits: list[WebHit]) -> int:
    seen = {(hit.url, hit.status) for hit in report.web}
    added = 0
    for hit in hits:
        key = (hit.url, hit.status)
        if not hit.url or key in seen:
            continue
        seen.add(key)
        report.web.append(hit)
        added += 1
    return added


def _extend_findings(report: ScanReport, found: list[Finding]) -> int:
    seen = {(item.template_id, item.matched_at, item.severity) for item in report.findings}
    added = 0
    for item in found:
        key = (item.template_id, item.matched_at, item.severity)
        if key in seen:
            continue
        seen.add(key)
        report.findings.append(item)
        added += 1
    return added


def _read_nmap(path: Path, target: str, report: ScanReport) -> list[Host]:
    try:
        return parse_nmap_xml(path.read_text(encoding="utf-8", errors="replace"))
    except ValueError as exc:
        report.notes.append(f"nmap xml for {target}: {exc}")
        return []


def _execute(argv: list[str], timeout: int | None) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, f"{argv[0]} timed out after {timeout}s"
    err = (completed.stderr or "").strip()
    if completed.returncode != 0 and not err:
        err = f"{argv[0]} exited {completed.returncode}"
    return completed.returncode, err


def _ran(report: ScanReport, tool: str) -> None:
    if tool not in report.ran:
        report.ran.append(tool)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _stem(value: str) -> str:
    cleaned = []
    for ch in value:
        cleaned.append(ch if ch.isalnum() or ch in "._-" else "_")
    stem = "".join(cleaned).strip("._")
    return stem[:120] or "target"


def _emit(callback: EventCallback | None, event: str, **data: object) -> None:
    if callback is not None:
        callback(event, data)


def tools_all_skipped(report: ScanReport) -> bool:
    return not report.ran and all(
        any(item.tool == name for item in report.skipped) for name in _TOOLS
    )
