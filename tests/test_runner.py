import subprocess
from pathlib import Path

from trawl.config import Config
from trawl.runner import run_scan, tools_all_skipped


def _install_fakes(monkeypatch, fixtures: Path, nmap_name: str = "nmap_basic.xml"):
    def fake_run(argv, **kwargs):
        assert isinstance(argv, list)
        assert kwargs.get("shell") in (None, False)
        if argv[0] == "nmap":
            Path(argv[argv.index("-oX") + 1]).write_text((fixtures / nmap_name).read_text())
        elif argv[0] == "ffuf":
            Path(argv[argv.index("-o") + 1]).write_text((fixtures / "ffuf_basic.json").read_text())
        elif argv[0] == "nuclei":
            Path(argv[argv.index("-output") + 1]).write_text(
                (fixtures / "nuclei_basic.jsonl").read_text()
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("trawl.runner.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("trawl.runner.subprocess.run", fake_run)


def test_live_run_parses_fixtures_without_scanning(tmp_path, fixtures, monkeypatch):
    _install_fakes(monkeypatch, fixtures)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n")
    cfg = Config()
    cfg.output_dir = str(tmp_path / "out")
    cfg.ffuf.wordlist = str(wordlist)
    cfg.timeout = 5
    seen = []
    report = run_scan(["10.10.11.42"], cfg, callback=lambda event, data: seen.append(event))
    assert seen[0] == "start"
    assert len(report.open_ports()) == 4
    assert len(report.web) == 3
    # info is in the fixture; default severity leaves it out
    assert {item.severity for item in report.findings} == {"medium", "high"}
    assert report.counts["nmap"] == 4
    assert any(argv[0] == "ffuf" and "https://storage.htb/FUZZ" in argv for argv in report.commands)
    assert (tmp_path / "out" / "nmap" / "10.10.11.42.xml").is_file()


def test_dry_run_does_not_execute_or_create_output(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("dry-run called subprocess")

    monkeypatch.setattr("trawl.runner.subprocess.run", boom)
    monkeypatch.setattr("trawl.runner.shutil.which", lambda name: f"/usr/bin/{name}")
    cfg = Config()
    cfg.output_dir = str(tmp_path / "out")
    cfg.ffuf.wordlist = str(tmp_path / "missing.txt")
    report = run_scan(["10.10.11.42"], cfg, dry_run=True, http_ports=[80, 443])
    assert any(argv[0] == "nmap" for argv in report.commands)
    assert any("http://10.10.11.42/FUZZ" in argv for argv in report.commands)
    assert any("https://10.10.11.42/FUZZ" in argv for argv in report.commands)
    assert any("wordlist isn't there yet" in note for note in report.notes)
    assert not (tmp_path / "out").exists()


def test_plain_dry_run_does_not_invent_web_ports(monkeypatch):
    monkeypatch.setattr("trawl.runner.shutil.which", lambda name: f"/usr/bin/{name}")
    cfg = Config()
    cfg.ffuf.wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    report = run_scan(["10.10.11.42"], cfg, dry_run=True)
    assert [argv[0] for argv in report.commands] == ["nmap"]
    assert any("--http-ports" in note or "http service" in note for note in report.notes)


def test_missing_tool_and_wordlist_are_skipped(tmp_path, fixtures, monkeypatch):
    _install_fakes(monkeypatch, fixtures)

    def which(name: str):
        if name == "ffuf":
            return None
        return f"/usr/bin/{name}"

    monkeypatch.setattr("trawl.runner.shutil.which", which)
    cfg = Config()
    cfg.output_dir = str(tmp_path / "out")
    cfg.ffuf.wordlist = str(tmp_path / "words.txt")
    report = run_scan(["http://storage.htb"], cfg, skip={"nmap"})
    assert any(item.tool == "ffuf" and "PATH" in item.reason for item in report.skipped)
    assert "ffuf" not in report.ran
    assert "nuclei" in report.ran
    assert report.findings

    monkeypatch.setattr("trawl.runner.shutil.which", lambda name: f"/usr/bin/{name}")
    cfg.ffuf.wordlist = str(tmp_path / "nope.txt")
    report = run_scan(["http://storage.htb"], cfg, skip={"nmap"})
    assert any(item.tool == "ffuf" and "wordlist" in item.reason for item in report.skipped)
    assert "ffuf" not in report.ran


def test_nothing_on_path_skips_everything(monkeypatch):
    monkeypatch.setattr("trawl.runner.shutil.which", lambda name: None)
    report = run_scan(["10.10.11.42"], Config())
    assert tools_all_skipped(report)
    assert report.commands == []
    assert report.nothing_caught()


def test_down_host_leaves_the_web_tools_idle(tmp_path, fixtures, monkeypatch):
    _install_fakes(monkeypatch, fixtures, nmap_name="nmap_down.xml")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("a\n")
    cfg = Config()
    cfg.output_dir = str(tmp_path / "out")
    cfg.ffuf.wordlist = str(wordlist)
    report = run_scan(["10.10.11.99"], cfg)
    assert report.nothing_caught()
    assert report.counts["nmap"] == 0
    assert "ffuf" not in report.ran
    assert any("sat this one out" in note for note in report.notes)
