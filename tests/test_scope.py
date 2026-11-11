import pytest

from trawl.errors import TrawlError
from trawl.scope import enforce_scope, in_scope, load_scope
from trawl.targets import normalise_targets, validate_target

ENTRIES = ["10.10.11.0/24", "*.htb", "lab.local"]


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("10.10.11.42", True),
        ("http://10.10.11.9:8080/admin", True),
        ("storage.htb", True),
        ("http://a.b.htb", True),
        ("LAB.LOCAL", True),
        ("10.10.11.0/28", True),
        ("10.10.12.1", False),
        ("10.10.11.0/16", False),
        ("evil.nothtb", False),
        ("htb", False),
        ("nothtb", False),
    ],
)
def test_scope_membership(target, expected):
    assert in_scope(target, ENTRIES) is expected


def test_hostname_does_not_inherit_a_cidr():
    assert in_scope("storage.htb", ["10.10.11.0/24"]) is False


def test_out_of_scope_is_an_error():
    with pytest.raises(TrawlError, match="outside scope"):
        enforce_scope(["8.8.8.8", "10.10.11.42"], ENTRIES)


def test_scope_file_ignores_comments(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text("# lab\n\n10.10.11.0/24\n*.htb\n")
    assert load_scope(path) == ["10.10.11.0/24", "*.htb"]


def test_scope_file_rejects_urls_and_empties(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text("http://storage.htb\n")
    with pytest.raises(TrawlError, match="not urls"):
        load_scope(path)
    path.write_text("# nothing\n\n")
    with pytest.raises(TrawlError, match="empty"):
        load_scope(path)


def test_targets_are_picky():
    assert validate_target("http://storage.htb/app/") == "http://storage.htb/app"
    assert normalise_targets(["10.10.11.42", "10.10.11.42"]) == ["10.10.11.42"]
    with pytest.raises(TrawlError):
        validate_target("10.10.11.42;id")
    with pytest.raises(TrawlError):
        validate_target("-Pn")
    with pytest.raises(TrawlError):
        validate_target("http://user:pass@storage.htb")
    with pytest.raises(TrawlError):
        validate_target("http://storage.htb/app?x=1")
    with pytest.raises(TrawlError):
        validate_target("999.1.1.1")
    with pytest.raises(TrawlError, match="give me a target"):
        normalise_targets([])
