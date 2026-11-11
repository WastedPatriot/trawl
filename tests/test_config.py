import pytest

from trawl.config import Config, load_config
from trawl.errors import TrawlError


def test_toml_overrides_and_timeout_zero_means_wait(tmp_path):
    path = tmp_path / "trawl.toml"
    path.write_text(
        """
output_dir = "box"
require_scope = true
timeout = 0

[nmap]
top_ports = 50
timing = "t3"
scripts = true
skip_ping = false

[ffuf]
threads = 12
wordlist = "/tmp/words.txt"
extensions = [".php", "bak"]
filter_codes = [404, 403]

[nuclei]
severity = ["high", "critical"]
rate_limit = 20
"""
    )
    cfg = load_config(path)
    assert cfg.output_dir == "box"
    assert cfg.require_scope is True
    assert cfg.timeout is None
    assert cfg.nmap.top_ports == 50
    assert cfg.nmap.timing == "T3"
    assert cfg.nmap.scripts is True
    assert cfg.nmap.skip_ping is False
    assert cfg.ffuf.threads == 12
    assert cfg.ffuf.extensions == ["php", "bak"]
    assert cfg.nuclei.severity == ["high", "critical"]


def test_unknown_key_and_bad_timing(tmp_path):
    path = tmp_path / "trawl.toml"
    path.write_text("favourite_colour = 'teal'\n")
    with pytest.raises(TrawlError, match="unknown config keys"):
        load_config(path)
    path.write_text("[nmap]\ntiming = 'T9'\n")
    with pytest.raises(TrawlError, match="timing"):
        load_config(path)


def test_defaults_are_lab_shaped():
    cfg = Config()
    cfg.validate()
    assert cfg.nmap.skip_ping is True
    assert cfg.nmap.service_detection is True
    assert cfg.nmap.scripts is False
    assert cfg.nuclei.severity == ["medium", "high", "critical"]
    assert cfg.timeout == 1800
