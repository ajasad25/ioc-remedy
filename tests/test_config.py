"""Path resolution -- the thing that made the original scripts unusable elsewhere."""
import os

import pytest

from ioc_remedy.config import Config, ENV_PREFIX


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            monkeypatch.delenv(key, raising=False)


def test_workdir_defaults_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert Config().workdir == tmp_path.resolve()


def test_explicit_workdir_wins_over_environment(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_PREFIX + "HOME_DIR", str(tmp_path / "from-env"))
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    assert Config(workdir=str(explicit)).workdir == explicit.resolve()


def test_environment_is_used_when_no_argument(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_PREFIX + "HOME_DIR", str(tmp_path))
    assert Config().workdir == tmp_path.resolve()


def test_data_dir_defaults_under_workdir(tmp_path):
    config = Config(workdir=str(tmp_path))
    assert config.data_dir == tmp_path.resolve() / "data"


def test_data_creates_the_directory_on_demand(tmp_path):
    config = Config(workdir=str(tmp_path))
    path = config.data("infected-configs.json")
    assert path.parent.is_dir()
    assert path.name == "infected-configs.json"


def test_accounts_parse_from_a_comma_separated_string(monkeypatch):
    monkeypatch.setenv(ENV_PREFIX + "ACCOUNTS", "alice, bob ,")
    assert Config().accounts == ["alice", "bob"]


def test_accounts_default_to_empty_meaning_use_gh_as_configured():
    assert Config().accounts == []


def test_require_engine_explains_itself_when_missing(tmp_path):
    config = Config(workdir=str(tmp_path), engine=str(tmp_path / "absent"))
    assert not config.engine_available
    with pytest.raises(SystemExit) as excinfo:
        config.require_engine()
    assert "ioc-guard" in str(excinfo.value)


def test_no_absolute_developer_paths_remain_in_the_package():
    # The specific regression this refactor exists to prevent.
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / "src"
    offenders = []
    for path in root.rglob("*.py"):
        text = path.read_text()
        for needle in ("/Users/", "/private/tmp/claude-"):
            if needle in text:
                offenders.append("{}: {}".format(path.name, needle))
    assert not offenders, offenders
