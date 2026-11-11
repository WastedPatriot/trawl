from pathlib import Path

from trawl.commands import ffuf_argv, http_urls_from_hosts, nmap_argv, nuclei_argv
from trawl.config import Config
from trawl.parse import parse_nmap_xml


def test_nmap_command_is_a_service_scan():
    cfg = Config()
    argv = nmap_argv("10.10.11.42", cfg, Path("out.xml"))
    assert argv[0] == "nmap"
    assert "-Pn" in argv
    assert "-sV" in argv
    assert "-sC" not in argv
    assert "--top-ports" in argv
    assert argv[-1] == "10.10.11.42"
    assert isinstance(argv, list)

    cfg.nmap.scripts = True
    cfg.nmap.skip_ping = False
    cfg.nmap.extra = ["--version-intensity", "2"]
    argv = nmap_argv("storage.htb", cfg, Path("out.xml"))
    assert "-sC" in argv
    assert "-Pn" not in argv
    assert "--version-intensity" in argv


def test_ffuf_and_nuclei_commands():
    cfg = Config()
    cfg.ffuf.wordlist = "/tmp/words with space.txt"
    ffuf = ffuf_argv("http://storage.htb:8080/app", cfg, Path("out.json"))
    assert ffuf[0] == "ffuf"
    assert "http://storage.htb:8080/app/FUZZ" in ffuf
    assert "/tmp/words with space.txt" in ffuf
    assert "-noninteractive" in ffuf
    assert "-of" in ffuf and "json" in ffuf

    nuclei = nuclei_argv("https://storage.htb", cfg, Path("out.jsonl"))
    assert nuclei[0] == "nuclei"
    assert "-jsonl" in nuclei
    assert "-disable-update-check" in nuclei
    assert "medium,high,critical" in nuclei
    assert "-target" in nuclei


def test_http_urls_from_the_sample_scan(fixtures):
    hosts = parse_nmap_xml((fixtures / "nmap_basic.xml").read_text())
    assert http_urls_from_hosts(hosts) == [
        "http://storage.htb",
        "https://storage.htb",
        "http://storage.htb:8080",
    ]
