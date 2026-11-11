"""Argument parsing and the order of operations. The tools live elsewhere."""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from trawl import __version__
from trawl.config import load_config, resolve_config_path
from trawl.easter import show_catch
from trawl.errors import TrawlError
from trawl.report import write_reports
from trawl.runner import run_scan, tools_all_skipped
from trawl.scope import enforce_scope, load_scope
from trawl.targets import load_lines, normalise_targets
from trawl.ui import (
    finished_line,
    live_progress,
    make_console,
    on_progress,
    show_banner,
    show_commands,
    show_notes,
    show_scope_nudge,
    show_summary,
    show_wrote,
)

_TOOLS = {"nmap", "ffuf", "nuclei"}


def main(argv: list[str] | None = None, console: Console | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = console or make_console()
    if args.catch_of_the_day:
        show_catch(console)
        return 0
    try:
        return _run(args, console)
    except TrawlError as exc:
        console.print(f"[trawl.warn]{escape(str(exc))}[/]")
        return 2
    except KeyboardInterrupt:
        console.print("\n[trawl.warn]hauled in early[/]")
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trawl",
        description=(
            "Run nmap, then ffuf on anything that speaks HTTP, then nuclei. "
            "Write one report. Authorised targets only."
        ),
        epilog="Tight lines. Only scan what you are allowed to.",
    )
    parser.add_argument("targets", nargs="*", help="hosts, CIDRs, or http(s) URLs")
    parser.add_argument(
        "-t",
        "--target-file",
        metavar="FILE",
        help="extra targets, one per line (# comments ignored)",
    )
    parser.add_argument("--scope", metavar="FILE", help="refuse anything that doesn't match")
    parser.add_argument("-c", "--config", metavar="FILE", help="TOML config")
    parser.add_argument(
        "-o",
        "--output",
        metavar="DIR",
        help="output directory (default trawl-out)",
    )
    parser.add_argument("--top-ports", type=int, metavar="N", help="nmap --top-ports")
    parser.add_argument(
        "--http-ports",
        metavar="PORTS",
        help="assume these web ports, comma-separated. 443, 8443 and 4443 are https",
    )
    parser.add_argument("--wordlist", metavar="FILE", help="wordlist for ffuf")
    parser.add_argument(
        "--severity",
        metavar="LIST",
        help="nuclei severities, comma-separated (default medium,high,critical)",
    )
    parser.add_argument("--skip", metavar="TOOLS", help="skip tools: nmap,ffuf,nuclei")
    parser.add_argument("--scripts", action="store_true", help="add nmap -sC (default scripts)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the commands and don't run them",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show tool stderr when something fails",
    )
    parser.add_argument("--version", action="version", version=f"trawl {__version__}")
    parser.add_argument("--catch-of-the-day", action="store_true", help=argparse.SUPPRESS)
    return parser


def _run(args: argparse.Namespace, console: Console) -> int:
    cfg = load_config(resolve_config_path(args.config))
    if args.output:
        cfg.output_dir = args.output
    if args.scope:
        cfg.scope_file = args.scope
    if args.top_ports is not None:
        cfg.nmap.top_ports = args.top_ports
    if args.wordlist:
        cfg.ffuf.wordlist = args.wordlist
    if args.severity:
        cfg.nuclei.severity = [part.strip() for part in args.severity.split(",") if part.strip()]
    if args.scripts:
        cfg.nmap.scripts = True
    cfg.validate()

    skip = _parse_skip(args.skip)
    if skip >= _TOOLS:
        raise TrawlError("that's every tool. nothing left to do")
    http_ports = _parse_ports(args.http_ports)

    raw = list(args.targets)
    if args.target_file:
        raw.extend(load_lines(Path(args.target_file)))
    targets = normalise_targets(raw)

    if cfg.require_scope and not cfg.scope_file:
        raise TrawlError("require_scope is set, and there's no scope file")
    if cfg.scope_file:
        scope_path = Path(cfg.scope_file)
        if not scope_path.is_file():
            raise TrawlError(f"scope file not found: {scope_path}")
        enforce_scope(targets, load_scope(scope_path))

    show_banner(
        console,
        targets=targets,
        scope=cfg.scope_file,
        output=cfg.output_dir,
        dry_run=args.dry_run,
    )
    if not cfg.scope_file and not args.dry_run:
        show_scope_nudge(console)

    verbose = args.verbose

    def callback(event: str, data: dict) -> None:
        if progress is None or task is None:
            return
        on_progress(progress, task, event, data)
        if event != "done":
            return
        tool = str(data.get("tool") or "")
        count = int(data.get("count") or 0)
        target = escape(str(data.get("target") or ""))
        progress.console.print(f"{tool}  {target}  [trawl.muted]{finished_line(tool, count)}[/]")
        if verbose and data.get("error"):
            progress.console.print(f"[trawl.muted]{escape(str(data['error']))}[/]")

    progress = None
    task = None
    if args.dry_run:
        report = run_scan(
            targets,
            cfg,
            dry_run=True,
            skip=skip,
            http_ports=http_ports,
        )
    else:
        with live_progress(console) as progress:
            task = progress.add_task("casting off", total=None)
            report = run_scan(
                targets,
                cfg,
                dry_run=False,
                skip=skip,
                http_ports=http_ports,
                callback=callback,
            )
        progress = None
        task = None

    show_notes(console, report)
    if args.dry_run:
        show_commands(report.commands)
        return 0

    paths = write_reports(Path(cfg.output_dir), report)
    show_summary(console, report)
    show_wrote(console, [str(path) for path in paths])
    if tools_all_skipped(report) or not report.ran:
        return 1
    return 0


def _parse_skip(raw: str | None) -> set[str]:
    if not raw:
        return set()
    skip: set[str] = set()
    for part in raw.split(","):
        name = part.strip().lower()
        if not name:
            continue
        if name not in _TOOLS:
            raise TrawlError(f"can't skip {name}. tools are nmap, ffuf, nuclei")
        skip.add(name)
    return skip


def _parse_ports(raw: str | None) -> list[int]:
    if not raw:
        return []
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit() or not 1 <= int(part) <= 65535:
            raise TrawlError(f"bad port: {part}")
        ports.append(int(part))
    return ports


if __name__ == "__main__":
    sys.exit(main())
