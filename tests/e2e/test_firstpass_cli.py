import shlex
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from firstpass import __version__
from firstpass.cli import app
from firstpass.lib.config import Config


runner = CliRunner()


@dataclass
class ConfigTest:
    config: Config | None
    config_path: Path


@pytest.fixture(scope="function")
def default_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config = Config()
    config.to_yaml(config_path)
    config_test = ConfigTest(config=config, config_path=config_path)
    return config_test


@pytest.fixture(scope="function")
def vault_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    vault_file = tmp_path / "vault"
    config = Config(vault_file=vault_file)
    config.to_yaml(config_path)
    config_test = ConfigTest(config=config, config_path=config_path)
    return config_test


@pytest.fixture(scope="function")
def nonexistent_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config_test = ConfigTest(config=None, config_path=config_path)
    return config_test


@pytest.fixture(scope="function")
def exists_but_empty_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config_path.touch()
    config_test = ConfigTest(config=None, config_path=config_path)
    return config_test


@pytest.fixture(scope="function")
def invalid_schema_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    with open(config_path, "w", encoding="utf-8") as f:
        f.write("not a valid config")
    config_test = ConfigTest(config=None, config_path=config_path)
    return config_test


def test_version():
    command = shlex.split("version")
    result = runner.invoke(app, command)
    assert result.exit_code == 0
    output = result.stdout.strip()
    assert output == __version__


@pytest.mark.parametrize(
    "config_test_str, command_input, want_exit_code",
    [
        ("default_config_test", "n\n", 1),
        ("default_config_test", "y\n", 0),
        ("vault_config_test", "n\n", 1),
        ("vault_config_test", "y\n", 0),
        ("nonexistent_config_test", None, 0),
        ("exists_but_empty_config_test", None, 0),
    ],
)
def test_init_config(
    config_test_str: str,
    command_input: str | None,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    command = shlex.split(f"init config --config-path {config_test.config_path}")
    result = runner.invoke(app, command, input=command_input)
    assert result.exit_code == want_exit_code
    if want_exit_code != 0:
        return
    new_config = Config.from_yaml(config_test.config_path)
    assert new_config == Config()


@pytest.mark.parametrize(
    "config_test_str, want_exit_code",
    [
        ("default_config_test", 0),
        ("vault_config_test", 0),
    ],
)
def test_config_list_keys(
    config_test_str: str, want_exit_code: int, request: pytest.FixtureRequest
):
    config_test = request.getfixturevalue(config_test_str)
    command = shlex.split(f"config --config-path {config_test.config_path} list-keys")
    result = runner.invoke(app, command)
    assert result.exit_code == want_exit_code
    if want_exit_code != 0:
        return
    output = result.stdout.strip()
    got = set(output.split("\n"))
    assert got == config_test.config.list_keys()


@pytest.mark.parametrize(
    "config_test_str, key, want_exit_code",
    [
        ("default_config_test", "local", 0),
        ("default_config_test", "vault_file", 0),
        ("default_config_test", "nonexistent_key", 1),
        ("vault_config_test", "local", 0),
        ("vault_config_test", "vault_file", 0),
        ("vault_config_test", "nonexistent_key", 1),
    ],
)
def test_config_get(
    config_test_str: str, key: str, want_exit_code: int, request: pytest.FixtureRequest
):
    config_test = request.getfixturevalue(config_test_str)
    command = shlex.split(f"config --config-path {config_test.config_path} get {key}")
    result = runner.invoke(app, command)
    assert result.exit_code == want_exit_code
    if want_exit_code != 0:
        return
    output = result.stdout.strip()
    value = str(getattr(config_test.config, key))
    assert value in output


@pytest.mark.parametrize(
    "config_test_str, key, value, want_exit_code",
    [
        ("default_config_test", "local", "True", 0),
        ("default_config_test", "local", "notabool", 1),
        ("default_config_test", "vault_file", "newvault", 0),
        ("default_config_test", "nonexistent_key", "doesntmatter", 1),
        ("vault_config_test", "local", "False", 0),
        ("vault_config_test", "local", "notabool", 1),
        ("vault_config_test", "vault_file", "newvault", 0),
        ("vault_config_test", "nonexistent_key", "doesntmatter", 1),
    ],
)
def test_config_set(
    config_test_str: str,
    key: str,
    value: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    command = shlex.split(
        f"config --config-path {config_test.config_path} set {key} {value}"
    )
    result = runner.invoke(app, command)
    assert result.exit_code == want_exit_code
    if want_exit_code != 0:
        return
    if Config.model_fields[key].annotation is bool:
        want_value = value == "True"
    else:
        want_value = Config.model_fields[key].annotation(value)  # type: ignore
    updated_config = Config.from_yaml(config_test.config_path)
    got_value = getattr(updated_config, key)
    assert got_value == want_value
