"""Defaults, then a TOML file, then whatever the flags say."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from trawl.errors import TrawlError

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
_TIMINGS = {f"T{i}" for i in range(6)}
_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
_EXTRA_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-=.,:_/+")


@dataclass
class NmapOptions:
    top_ports: int = 1000
    timing: str = "T4"
    # HTB boxes often ignore ping. Skip it unless a config says otherwise.
    skip_ping: bool = True
    service_detection: bool = True
    scripts: bool = False
    extra: list[str] = field(default_factory=list)


@dataclass
class FfufOptions:
    wordlist: str = DEFAULT_WORDLIST
    threads: int = 40
    extensions: list[str] = field(default_factory=lambda: ["php", "html", "txt"])
    filter_codes: list[int] = field(default_factory=lambda: [404])
    match_codes: str = "200,204,301,302,307,401,403"
    rate: int = 0


@dataclass
class NucleiOptions:
    severity: list[str] = field(default_factory=lambda: ["medium", "high", "critical"])
    rate_limit: int = 150
    templates: list[str] = field(default_factory=list)


@dataclass
class Config:
    output_dir: str = "trawl-out"
    scope_file: str | None = None
    require_scope: bool = False
    # Per tool invocation. 0 in TOML means "wait forever", which is your choice.
    timeout: int | None = 1800
    nmap: NmapOptions = field(default_factory=NmapOptions)
    ffuf: FfufOptions = field(default_factory=FfufOptions)
    nuclei: NucleiOptions = field(default_factory=NucleiOptions)

    def validate(self) -> None:
        if self.nmap.top_ports < 1:
            raise TrawlError("top_ports needs to be at least 1")
        timing = self.nmap.timing.upper()
        if timing not in _TIMINGS:
            raise TrawlError(f"nmap timing must be one of {', '.join(sorted(_TIMINGS))}")
        self.nmap.timing = timing
        for token in self.nmap.extra:
            if not token or any(ch not in _EXTRA_OK for ch in token):
                raise TrawlError(f"nmap extra argument looks off: {token!r}")

        if not 1 <= self.ffuf.threads <= 200:
            raise TrawlError("ffuf threads should sit between 1 and 200")
        if self.ffuf.rate < 0:
            raise TrawlError("ffuf rate can't be negative")
        _check_codes(self.ffuf.filter_codes, "filter_codes")
        if self.ffuf.match_codes:
            codes = [part.strip() for part in self.ffuf.match_codes.split(",") if part.strip()]
            parsed: list[int] = []
            for part in codes:
                if not part.isdigit():
                    raise TrawlError(f"match_codes should be status numbers, not {part!r}")
                parsed.append(int(part))
            _check_codes(parsed, "match_codes")
        cleaned: list[str] = []
        for ext in self.ffuf.extensions:
            ext = ext.strip().lstrip(".")
            if not ext or any(ch in ext for ch in " /\\"):
                raise TrawlError(f"bad ffuf extension: {ext!r}")
            cleaned.append(ext)
        self.ffuf.extensions = cleaned

        if self.nuclei.rate_limit < 0:
            raise TrawlError("nuclei rate_limit can't be negative")
        severities = [part.strip().lower() for part in self.nuclei.severity if part.strip()]
        unknown = [part for part in severities if part not in _SEVERITIES]
        if unknown:
            raise TrawlError(f"unknown nuclei severity: {', '.join(unknown)}")
        self.nuclei.severity = severities
        if self.timeout is not None and self.timeout < 0:
            raise TrawlError("timeout can't be negative")


def load_config(path: Path | None) -> Config:
    cfg = Config()
    if path is None:
        cfg.validate()
        return cfg
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TrawlError(f"couldn't read config {path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise TrawlError(f"config {path} isn't valid TOML: {exc}") from exc
    if not isinstance(raw, dict):
        raise TrawlError(f"config {path} needs a TOML table at the top")
    _apply(cfg, raw, path)
    cfg.validate()
    return cfg


def resolve_config_path(explicit: str | None) -> Path | None:
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise TrawlError(f"config not found: {path}")
        return path
    local = Path("trawl.toml")
    if local.is_file():
        return local
    home = Path.home() / ".config" / "trawl" / "config.toml"
    if home.is_file():
        return home
    return None


def _apply(cfg: Config, raw: dict, path: Path) -> None:
    known = {"output_dir", "scope_file", "require_scope", "timeout", "nmap", "ffuf", "nuclei"}
    unexpected = sorted(set(raw) - known)
    if unexpected:
        raise TrawlError(f"unknown config keys in {path}: {', '.join(unexpected)}")

    if "output_dir" in raw:
        cfg.output_dir = _as_str(raw["output_dir"], "output_dir")
    if "scope_file" in raw:
        value = raw["scope_file"]
        if value is None or value == "":
            cfg.scope_file = None
        else:
            cfg.scope_file = _as_str(value, "scope_file")
    if "require_scope" in raw:
        cfg.require_scope = _as_bool(raw["require_scope"], "require_scope")
    if "timeout" in raw:
        timeout = _as_int(raw["timeout"], "timeout")
        cfg.timeout = None if timeout == 0 else timeout

    if "nmap" in raw:
        _apply_nmap(cfg.nmap, _as_table(raw["nmap"], "nmap"))
    if "ffuf" in raw:
        _apply_ffuf(cfg.ffuf, _as_table(raw["ffuf"], "ffuf"))
    if "nuclei" in raw:
        _apply_nuclei(cfg.nuclei, _as_table(raw["nuclei"], "nuclei"))


def _apply_nmap(opts: NmapOptions, raw: dict) -> None:
    _reject_unknown(raw, {"top_ports", "timing", "skip_ping", "service_detection", "scripts", "extra"}, "nmap")
    if "top_ports" in raw:
        opts.top_ports = _as_int(raw["top_ports"], "nmap.top_ports")
    if "timing" in raw:
        opts.timing = _as_str(raw["timing"], "nmap.timing")
    if "skip_ping" in raw:
        opts.skip_ping = _as_bool(raw["skip_ping"], "nmap.skip_ping")
    if "service_detection" in raw:
        opts.service_detection = _as_bool(raw["service_detection"], "nmap.service_detection")
    if "scripts" in raw:
        opts.scripts = _as_bool(raw["scripts"], "nmap.scripts")
    if "extra" in raw:
        extra = raw["extra"]
        if not isinstance(extra, list) or not all(isinstance(item, str) for item in extra):
            raise TrawlError("nmap.extra needs a list of strings")
        opts.extra = list(extra)


def _apply_ffuf(opts: FfufOptions, raw: dict) -> None:
    known = {"wordlist", "threads", "extensions", "filter_codes", "match_codes", "rate"}
    _reject_unknown(raw, known, "ffuf")
    if "wordlist" in raw:
        opts.wordlist = _as_str(raw["wordlist"], "ffuf.wordlist")
    if "threads" in raw:
        opts.threads = _as_int(raw["threads"], "ffuf.threads")
    if "extensions" in raw:
        opts.extensions = _as_str_list(raw["extensions"], "ffuf.extensions")
    if "filter_codes" in raw:
        opts.filter_codes = _as_int_list(raw["filter_codes"], "ffuf.filter_codes")
    if "match_codes" in raw:
        opts.match_codes = _as_str(raw["match_codes"], "ffuf.match_codes")
    if "rate" in raw:
        opts.rate = _as_int(raw["rate"], "ffuf.rate")


def _apply_nuclei(opts: NucleiOptions, raw: dict) -> None:
    _reject_unknown(raw, {"severity", "rate_limit", "templates"}, "nuclei")
    if "severity" in raw:
        opts.severity = _as_str_list(raw["severity"], "nuclei.severity")
    if "rate_limit" in raw:
        opts.rate_limit = _as_int(raw["rate_limit"], "nuclei.rate_limit")
    if "templates" in raw:
        opts.templates = _as_str_list(raw["templates"], "nuclei.templates")


def _reject_unknown(raw: dict, known: set[str], where: str) -> None:
    unexpected = sorted(set(raw) - known)
    if unexpected:
        raise TrawlError(f"unknown {where} config keys: {', '.join(unexpected)}")


def _as_table(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise TrawlError(f"{name} needs to be a table")
    return value


def _as_str(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TrawlError(f"{name} needs a string")
    return value.strip()


def _as_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise TrawlError(f"{name} needs true or false")
    return value


def _as_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TrawlError(f"{name} needs an integer")
    return value


def _as_str_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TrawlError(f"{name} needs a list of strings")
    return [item.strip() for item in value if item.strip()]


def _as_int_list(value: object, name: str) -> list[int]:
    if not isinstance(value, list):
        raise TrawlError(f"{name} needs a list of integers")
    numbers: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise TrawlError(f"{name} needs a list of integers")
        numbers.append(item)
    return numbers


def _check_codes(codes: list[int], name: str) -> None:
    for code in codes:
        if not 100 <= code <= 599:
            raise TrawlError(f"{name} has a status that isn't a status: {code}")
