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


def test_version(default_config_test: ConfigTest):
    command = shlex.split(f"--config-path {default_config_test.config_path} version")
    result = runner.invoke(app, command)
    output = result.stdout.strip()
    assert output == __version__


@pytest.mark.parametrize(
    "config_test_str, want_exit_code",
    [
        ("default_config_test", 0),
        ("vault_config_test", 0),
        ("nonexistent_config_test", 1),
    ],
)
def test_config_reset(
    config_test_str: str, want_exit_code: int, request: pytest.FixtureRequest
):
    config_test = request.getfixturevalue(config_test_str)
    command = shlex.split(f"--config-path {config_test.config_path} config reset")
    result = runner.invoke(app, command)
    assert result.exit_code == want_exit_code
    if want_exit_code == 1:
        return
    config = Config.from_yaml(config_test.config_path)
    assert config == Config()
