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
    config: Config
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
    config_test = ConfigTest(config=Config(), config_path=config_path)
    return config_test


@pytest.fixture(scope="function")
def invalid_schema_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config = Config()
    with open(config_path, "w", encoding="utf-8") as f:
        f.write("not a valid config")
    config_test = ConfigTest(config=config, config_path=config_path)
    return config_test


def firstpass_cli(command: str, want_exit_code: int) -> str:
    result = runner.invoke(app, shlex.split(command))
    assert result.exit_code == want_exit_code
    return result.stdout.strip()


# This is used to test the main callback on the CLI which gets invoked on every command
# That's why something as simple as testing the version number has so many input parameters
# and can return non-zero exit codes!
@pytest.mark.parametrize(
    "config_test_str, want_exit_code",
    [
        ("default_config_test", 0),
        ("vault_config_test", 0),
        ("nonexistent_config_test", 1),
        ("invalid_schema_config_test", 1),
    ],
)
def test_version(
    config_test_str: str, want_exit_code: int, request: pytest.FixtureRequest
):
    config_test = request.getfixturevalue(config_test_str)
    command = f"--config-path {config_test.config_path} version"
    output = firstpass_cli(command, want_exit_code)
    if want_exit_code != 0:
        return
    assert output == __version__


@pytest.mark.parametrize(
    "config_test_str, want_exit_code",
    [
        ("default_config_test", 0),
        ("vault_config_test", 0),
    ],
)
def test_config_reset(
    config_test_str: str, want_exit_code: int, request: pytest.FixtureRequest
):
    config_test = request.getfixturevalue(config_test_str)
    command = f"--config-path {config_test.config_path} config reset"
    _ = firstpass_cli(command, want_exit_code)
    if want_exit_code != 0:
        return
    config = Config.from_yaml(config_test.config_path)
    assert config == Config()


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
    command = f"--config-path {config_test.config_path} config list-keys"
    output = firstpass_cli(command, want_exit_code)
    if want_exit_code != 0:
        return
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
    command = f"--config-path {config_test.config_path} config get {key}"
    output = firstpass_cli(command, want_exit_code)
    if want_exit_code != 0:
        return
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
    command = f"--config-path {config_test.config_path} config set {key} {value}"
    _ = firstpass_cli(command, want_exit_code)
    if want_exit_code != 0:
        return
    if Config.model_fields[key].annotation is bool:
        want_value = value == "True"
    else:
        want_value = Config.model_fields[key].annotation(value)  # type: ignore
    updated_config = Config.from_yaml(config_test.config_path)
    got_value = getattr(updated_config, key)
    assert got_value == want_value
