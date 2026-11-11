import subprocess
from pathlib import Path

import pytest

from trawl.cli import main


def test_help_hides_the_fish(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--dry-run" in out
    assert "Authorised targets only" in out
    assert "catch-of-the-day" not in out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "trawl 0.1.0" in capsys.readouterr().out


def test_catch_of_the_day(capsys):
    assert main(["--catch-of-the-day"]) == 0
    out = capsys.readouterr().out
    assert "catch of the day" in out
    assert "mullet" in out


def test_dry_run_prints_commands(tmp_path, capsys, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("dry-run should not spawn anything")

    monkeypatch.setattr("trawl.runner.subprocess.run", boom)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n")
    out = tmp_path / "out"
    code = main(
        [
            "10.10.11.42",
            "--dry-run",
            "--http-ports",
            "80,443",
            "--wordlist",
            str(wordlist),
            "-o",
            str(out),
            "--top-ports",
            "50",
        ]
    )
    assert code == 0
    text = capsys.readouterr().out
    assert "dry run" in text
    assert "--top-ports 50" in text
    assert "http://10.10.11.42/FUZZ" in text
    assert "https://10.10.11.42" in text
    assert "-disable-update-check" in text
    assert not out.exists()


def test_scope_and_bad_input_exit_2(tmp_path, capsys):
    scope = tmp_path / "scope.txt"
    scope.write_text("10.10.11.0/24\n")
    assert main(["8.8.8.8", "--scope", str(scope), "--dry-run"]) == 2
    assert "outside scope" in capsys.readouterr().out

    assert main(["10.10.11.42;id", "--dry-run"]) == 2
    assert main([]) == 2
    assert main(["--skip", "nmap,ffuf,nuclei", "10.10.11.42"]) == 2
    assert main(["--http-ports", "80,70000", "10.10.11.42", "--dry-run"]) == 2


def test_require_scope_without_a_file(tmp_path, capsys):
    config = tmp_path / "trawl.toml"
    config.write_text("require_scope = true\n")
    assert main(["-c", str(config), "10.10.11.42", "--dry-run"]) == 2
    assert "scope file" in capsys.readouterr().out


def test_target_file_and_live_fixtures(tmp_path, fixtures, capsys, monkeypatch):
    def fake_run(argv, **kwargs):
        assert isinstance(argv, list)
        if argv[0] == "nmap":
            Path(argv[argv.index("-oX") + 1]).write_text((fixtures / "nmap_basic.xml").read_text())
        elif argv[0] == "ffuf":
            Path(argv[argv.index("-o") + 1]).write_text((fixtures / "ffuf_basic.json").read_text())
        elif argv[0] == "nuclei":
            Path(argv[argv.index("-output") + 1]).write_text(
                (fixtures / "nuclei_basic.jsonl").read_text()
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("trawl.runner.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("trawl.runner.subprocess.run", fake_run)
    targets = tmp_path / "targets.txt"
    targets.write_text("# box\n10.10.11.42\n")
    scope = tmp_path / "scope.txt"
    scope.write_text("10.10.11.0/24\n*.htb\n")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n")
    out = tmp_path / "out"
    code = main(
        [
            "-t",
            str(targets),
            "--scope",
            str(scope),
            "--wordlist",
            str(wordlist),
            "-o",
            str(out),
        ]
    )
    captured = capsys.readouterr().out
    assert code == 0
    assert "storage.htb" in captured
    assert "Apache" in captured
    assert (out / "report.md").is_file()
    assert (out / "report.html").is_file()
    assert "nothing in the nets today" not in captured


def test_missing_tools_exit_1_and_still_write_a_report(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("trawl.runner.shutil.which", lambda name: None)
    out = tmp_path / "out"
    assert main(["10.10.11.42", "-o", str(out)]) == 1
    text = capsys.readouterr().out
    assert "not on PATH" in text
    assert "nothing in the nets today" in text
    assert (out / "report.md").is_file()


def test_down_host_says_the_nets_are_empty(tmp_path, fixtures, capsys, monkeypatch):
    def fake_run(argv, **kwargs):
        if argv[0] == "nmap":
            Path(argv[argv.index("-oX") + 1]).write_text((fixtures / "nmap_down.xml").read_text())
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("trawl.runner.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("trawl.runner.subprocess.run", fake_run)
    out = tmp_path / "out"
    code = main(["10.10.11.99", "--skip", "ffuf,nuclei", "-o", str(out)])
    assert code == 0
    assert "nothing in the nets today" in capsys.readouterr().out
