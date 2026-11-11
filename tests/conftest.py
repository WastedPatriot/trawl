from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Don't let a developer's ~/.config/trawl/config.toml leak into a test.
    monkeypatch.setattr("trawl.config.Path.home", lambda: tmp_path / "home")
