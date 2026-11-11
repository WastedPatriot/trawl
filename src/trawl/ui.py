"""The bit you actually look at while it runs."""

import shlex

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from trawl import __version__
from trawl.models import Port, ScanReport
from trawl.report import quiet_lines

THEME = Theme(
    {
        "trawl.title": "bold #9ee7dc",
        "trawl.muted": "dim",
        "trawl.warn": "#e0b15b",
        "trawl.good": "#b7d7a8",
        "sev.critical": "bold #e07a6a",
        "sev.high": "#e09a6a",
        "sev.medium": "#e0b15b",
        "sev.low": "#8eb4e3",
        "sev.info": "dim",
    }
)

_COUNT = {
    "nmap": ("open", "open"),
    "ffuf": ("path", "paths"),
    "nuclei": ("match", "matches"),
}


def make_console() -> Console:
    return Console(theme=THEME, highlight=False)


def show_banner(
    console: Console,
    *,
    targets: list[str],
    scope: str | None,
    output: str,
    dry_run: bool,
) -> None:
    noun = "target" if len(targets) == 1 else "targets"
    bits = [f"{len(targets)} {noun}", f"scope {scope or 'none'}", f"out {output}"]
    if dry_run:
        bits.append("dry run")
    console.print(
        Panel(
            "  ·  ".join(escape(bit) for bit in bits),
            title="trawl",
            subtitle=__version__,
            border_style="#7fd1c7",
            padding=(0, 1),
        )
    )


def show_scope_nudge(console: Console) -> None:
    console.print(
        "[trawl.muted]no scope file. only point this at things you're allowed to poke.[/]"
    )


def show_notes(console: Console, report: ScanReport) -> None:
    for item in report.skipped:
        console.print(f"[trawl.warn]skip[/]  {escape(item.tool)}  {escape(item.reason)}")
    for note in report.notes:
        console.print(f"[trawl.muted]{escape(note)}[/]")


def show_commands(commands: list[list[str]]) -> None:
    for argv in commands:
        print(shlex.join(argv), flush=True)


def show_summary(console: Console, report: ScanReport) -> None:
    rows = report.open_ports()
    if rows:
        table = Table(box=box.SIMPLE_HEAD, header_style="trawl.title", pad_edge=False)
        table.add_column("host")
        table.add_column("port", justify="right")
        table.add_column("service")
        table.add_column("version")
        for host, port in rows:
            table.add_row(
                Text(host.label),
                str(port.port),
                Text(port.service_label),
                Text(_short_version(port)),
            )
        console.print(table)

    if report.web:
        table = Table(box=box.SIMPLE_HEAD, header_style="trawl.title", pad_edge=False)
        table.add_column("status", justify="right")
        table.add_column("length", justify="right")
        table.add_column("url")
        for hit in sorted(report.web, key=lambda item: (item.status, item.url)):
            table.add_row(str(hit.status), str(hit.length), Text(hit.url))
        console.print(table)

    if report.findings:
        table = Table(box=box.SIMPLE_HEAD, header_style="trawl.title", pad_edge=False)
        table.add_column("sev")
        table.add_column("name")
        table.add_column("matched")
        ordered = sorted(
            report.findings,
            key=lambda item: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(item.severity, 9),
                item.name,
            ),
        )
        for finding in ordered:
            style = f"sev.{finding.severity}" if finding.severity in _SEV else "trawl.muted"
            table.add_row(
                Text(finding.severity, style=style),
                Text(finding.name),
                Text(finding.matched_at or finding.host),
            )
        console.print(table)

    for line in quiet_lines(report):
        console.print(f"[trawl.warn]{escape(line)}[/]")


def show_wrote(console: Console, paths: list[str]) -> None:
    for path in paths:
        console.print(f"[trawl.good]wrote[/] {escape(path)}")


def live_progress(console: Console) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def on_progress(progress: Progress, task: int, event: str, data: dict) -> None:
    if event != "start":
        return
    tool = str(data.get("tool") or "")
    target = escape(str(data.get("target") or ""))
    progress.update(task, description=f"{tool}  {target}")


_SEV = {"critical", "high", "medium", "low", "info"}


def _short_version(port: Port) -> str:
    # The full extrainfo belongs in the report. The terminal gets the one-liner.
    return " ".join(part for part in (port.product, port.version) if part)


def finished_line(tool: str, count: int) -> str:
    singular, plural = _COUNT.get(tool, ("result", "results"))
    noun = singular if count == 1 else plural
    return f"{count} {noun}"
