import shlex
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import Result
from pydantic import SecretStr
from typer.testing import CliRunner

from firstpass import __version__
from firstpass.cli import app
from firstpass.lib import (
    Config,
    LocalVault,
    Password,
    Secret,
    SecretPart,
    SecretsType,
    get_name_from_secrets_type,
)


runner = CliRunner()


@dataclass
class ConfigTest:
    config: Config | None
    config_path: Path
    password: str


@pytest.fixture(scope="function")
def default_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config = Config(local=True)
    config.to_yaml(config_path)
    config_test = ConfigTest(
        config=config, config_path=config_path, password="password"
    )
    return config_test


@pytest.fixture(scope="function")
def vault_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    vault_file = tmp_path / "vault"
    config = Config(local=True, vault_file=vault_file)
    config.to_yaml(config_path)
    config_test = ConfigTest(
        config=config, config_path=config_path, password="password"
    )
    return config_test


@pytest.fixture(scope="function")
def existing_empty_vault_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    vault_file = tmp_path / "vault"
    password = "password"
    LocalVault(password=password, file=vault_file)
    config = Config(local=True, vault_file=vault_file)
    config.to_yaml(config_path)
    config_test = ConfigTest(config=config, config_path=config_path, password=password)
    return config_test


@pytest.fixture(scope="function")
def existing_non_empty_vault_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    vault_file = tmp_path / "vault"
    password = "password"
    vault = LocalVault(password=password, file=vault_file)
    vault.set(
        secrets_type=SecretsType.passwords,
        name="pizza",
        secret=Password(
            label="Pizza",
            notes="is great",
            username="pepperoni",
            password=SecretStr("cheese"),
        ),
    )
    vault.set(
        secrets_type=SecretsType.passwords,
        name="pickles",
        secret=Password(
            label="Pickles",
            notes="are gross on pizza",
            username="cucumber",
            password=SecretStr("dill"),
        ),
    )
    vault.set(
        secrets_type=SecretsType.passwords,
        name="tickles",
        secret=Password(
            label="Tickles",
            notes="would be weird with pickles",
            username="fickles",
            password=SecretStr("onmytickles"),
        ),
    )
    config = Config(local=True, vault_file=vault_file)
    config.to_yaml(config_path)
    config_test = ConfigTest(config=config, config_path=config_path, password=password)
    return config_test


@pytest.fixture(scope="function")
def nonexistent_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config_test = ConfigTest(config=None, config_path=config_path, password="password")
    return config_test


@pytest.fixture(scope="function")
def exists_but_empty_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config_path.touch()
    config_test = ConfigTest(config=None, config_path=config_path, password="password")
    return config_test


@pytest.fixture(scope="function")
def invalid_schema_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    with open(config_path, "w", encoding="utf-8") as f:
        f.write("not a valid config")
    config_test = ConfigTest(config=None, config_path=config_path, password="password")
    return config_test


def run_cli(
    *, command_str: str, command_input: str | None, want_exit_code: int
) -> Result:
    command = shlex.split(command_str)
    result = runner.invoke(app, command, input=command_input)
    assert result.exit_code == want_exit_code
    return result


def test_version():
    command_str = "version"
    result = run_cli(command_str=command_str, command_input=None, want_exit_code=0)
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
    command_str = f"init config --config-path {config_test.config_path}"
    _ = run_cli(
        command_str=command_str,
        command_input=command_input,
        want_exit_code=want_exit_code,
    )
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
    command_str = f"config --config-path {config_test.config_path} list-keys"
    result = run_cli(
        command_str=command_str, command_input=None, want_exit_code=want_exit_code
    )
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
    command_str = f"config --config-path {config_test.config_path} get {key}"
    result = run_cli(
        command_str=command_str, command_input=None, want_exit_code=want_exit_code
    )
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
    command_str = f"config --config-path {config_test.config_path} set {key} {value}"
    _ = run_cli(
        command_str=command_str, command_input=None, want_exit_code=want_exit_code
    )
    if want_exit_code != 0:
        return
    if Config.model_fields[key].annotation is bool:
        want_value = value == "True"
    else:
        want_value = Config.model_fields[key].annotation(value)  # type: ignore
    updated_config = Config.from_yaml(config_test.config_path)
    got_value = getattr(updated_config, key)
    assert got_value == want_value


@pytest.mark.parametrize("secrets_type", [st for st in SecretsType])
def test_vault_list_parts(secrets_type: SecretsType, default_config_test: ConfigTest):
    secret_name = get_name_from_secrets_type(secrets_type)
    want_keys = secret_name.list_parts()
    command_str = f"vault --config-path {default_config_test.config_path} list-parts {secrets_type}"
    result = run_cli(command_str=command_str, command_input=None, want_exit_code=0)
    got_keys = result.stdout.strip().split("\n")
    assert len(got_keys) == len(want_keys)
    assert set(got_keys) == want_keys


@pytest.mark.parametrize(
    "config_test_str, command_input, password, want_exit_code",
    [
        ("vault_config_test", "password\ndifferentpassword", "password", 1),
        ("vault_config_test", "password\npassword", "password", 0),
        ("existing_empty_vault_config_test", "password\npassword", "password", 1),
    ],
)
def test_vault_init(
    config_test_str: str,
    command_input: str,
    password: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    command_str = f"vault --config-path {config_test.config_path} init"
    _ = run_cli(
        command_str=command_str,
        command_input=command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = LocalVault(password=password, file=config_test.config.vault_file)
    assert vault.can_open()


@pytest.mark.parametrize(
    "config_test_str, command_input, want_exit_code",
    [
        ("existing_empty_vault_config_test", "n\n", 1),
        ("existing_empty_vault_config_test", "y\n", 0),
        ("existing_non_empty_vault_config_test", "n\n", 1),
        ("existing_non_empty_vault_config_test", "y\n", 0),
    ],
)
def test_vault_remove(
    config_test_str: str,
    command_input: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    passworded_command_input = "\n".join((config_test.password, command_input))
    command_str = f"vault --config-path {config_test.config_path} remove"
    _ = run_cli(
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    assert not config_test.config.vault_file.exists()


@pytest.mark.parametrize(
    "config_test_str, secrets_type, want_exit_code",
    [
        ("existing_empty_vault_config_test", SecretsType.passwords, 0),
        ("existing_non_empty_vault_config_test", SecretsType.passwords, 0),
    ],
)
def test_vault_list_names(
    config_test_str: str,
    secrets_type: SecretsType,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    passworded_command_input = f"{config_test.password}\n"
    command_str = (
        f"vault --config-path {config_test.config_path} list-names {secrets_type}"
    )
    result = run_cli(
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = LocalVault(
        password=config_test.password, file=config_test.config.vault_file
    )
    want_names = vault.list_names(secrets_type)
    output = result.stdout.strip().split("\n")
    # Remove the Password: prompt
    output.pop(0)
    assert len(output) == len(want_names)
    assert set(output) == want_names


@pytest.mark.parametrize(
    "config_test_str, secrets_type, name, want_secret, command_input, want_exit_code",
    [
        (
            "existing_empty_vault_config_test",
            SecretsType.passwords,
            "pybites",
            Password(
                label="PyBites",
                notes="notes",
                username="daniel",
                password=SecretStr("password"),
            ),
            "pybites\npassword\ndifferentpassword\npassword\ndifferentpassword\npassword\npassword\nPyBites\nnotes\ndaniel\n",
            0,
        ),
        (
            "existing_empty_vault_config_test",
            SecretsType.passwords,
            "pybites",
            Password(
                label="PyBites",
                notes="notes",
                username="daniel",
                password=SecretStr("password"),
            ),
            "pybites\npassword\npassword\nPyBites\nnotes\ndaniel\n",
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            Password(
                label="PyBites",
                notes="notes",
                username="daniel",
                password=SecretStr("password"),
            ),
            "pizza\n",
            1,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pepperoni",
            Password(
                label="Pepperoni",
                notes="pizza",
                username="hungry",
                password=SecretStr("cheese"),
            ),
            "pepperoni\ncheese\ncheese\nPepperoni\npizza\nhungry\n",
            0,
        ),
    ],
)
def test_vault_new(
    config_test_str: str,
    secrets_type: SecretsType,
    name: str,
    want_secret: Secret,
    command_input: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    passworded_command_input = "\n".join((config_test.password, command_input))
    command_str = f"vault --config-path {config_test.config_path} new {secrets_type}"
    _ = run_cli(
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = LocalVault(
        password=config_test.password, file=config_test.config.vault_file
    )
    got_secret = vault.get(secrets_type, name)
    assert got_secret == want_secret


@pytest.mark.parametrize(
    "config_test_str, secrets_type, name, secret_part, show, copy, want_exit_code",
    [
        (
            "existing_empty_vault_config_test",
            SecretsType.passwords,
            "name_that_doesnt_exist",
            SecretPart.all,
            True,
            True,
            1,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.all,
            False,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.all,
            False,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.all,
            True,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.all,
            True,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pickles",
            SecretPart.label,
            False,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pickles",
            SecretPart.label,
            False,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pickles",
            SecretPart.label,
            True,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pickles",
            SecretPart.label,
            True,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.notes,
            False,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.notes,
            False,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.notes,
            True,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.notes,
            True,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.username,
            False,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.username,
            False,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.username,
            True,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.username,
            True,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.password,
            False,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.password,
            False,
            True,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.password,
            True,
            False,
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "tickles",
            SecretPart.password,
            True,
            True,
            0,
        ),
    ],
)
@patch("firstpass.cli.pyperclip.copy")
def test_vault_get(
    pyperclip_mock: MagicMock,
    config_test_str: str,
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
    show: bool,
    copy: bool,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    passworded_command_input = f"{config_test.password}\n"
    command_str = f"vault --config-path {config_test.config_path} get {secrets_type} {name} {secret_part} {'--show' if show else ''} {'--copy' if copy else ''}"
    result = run_cli(
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = LocalVault(
        password=config_test.password, file=config_test.config.vault_file
    )
    output = result.stdout.strip().split("\n")
    # Remove the Password: prompt
    output.pop(0)
    if secret_part == SecretPart.all:
        pyperclip_mock.assert_not_called()
        assert output[-1] == str(vault.get(secrets_type, name))
        return
    value = getattr(vault.get(secrets_type, name), secret_part)
    if secret_part == SecretPart.password and show:
        assert output[-1] == value.get_secret_value()
    else:
        assert output[-1] == str(value)
    if not copy:
        pyperclip_mock.assert_not_called()
        return
    pyperclip_mock.assert_called_with(
        value if secret_part != SecretPart.password else value.get_secret_value()
    )


@pytest.mark.parametrize(
    "config_test_str, secrets_type, name, secret_part, value, want_exit_code",
    [
        (
            "existing_empty_vault_config_test",
            SecretsType.passwords,
            "name_that_doesnt_exist",
            SecretPart.label,
            "new_label",
            1,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.all,
            "irrelevant",
            1,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "name_that_doesnt_exist",
            SecretPart.password,
            "newpassword",
            1,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.label,
            "new_label",
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.notes,
            "some notes",
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.username,
            "newusername",
            0,
        ),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "pizza",
            SecretPart.password,
            "supersecretpassword",
            0,
        ),
    ],
)
def test_vault_set(
    config_test_str: str,
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
    value: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    passworded_command_input = f"{config_test.password}\n"
    command_str = f"vault --config-path {config_test.config_path} set {secrets_type} {name} {secret_part} '{value}'"
    _ = run_cli(
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = LocalVault(
        password=config_test.password, file=config_test.config.vault_file
    )
    if secret_part == SecretPart.password:
        assert (
            getattr(vault.get(secrets_type, name), secret_part)
        ).get_secret_value() == value
        return
    assert getattr(vault.get(secrets_type, name), secret_part) == value


@pytest.mark.parametrize(
    "config_test_str, secrets_type, name, want_exit_code",
    [
        (
            "existing_empty_vault_config_test",
            SecretsType.passwords,
            "name_that_doesnt_exist",
            0,
        ),
        ("existing_non_empty_vault_config_test", SecretsType.passwords, "pizza", 0),
        ("existing_non_empty_vault_config_test", SecretsType.passwords, "pickles", 0),
        ("existing_non_empty_vault_config_test", SecretsType.passwords, "tickles", 0),
        (
            "existing_non_empty_vault_config_test",
            SecretsType.passwords,
            "name_that_doesnt_exist",
            0,
        ),
    ],
)
def test_vault_delete(
    config_test_str: str,
    secrets_type: SecretsType,
    name: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    config_test = request.getfixturevalue(config_test_str)
    passworded_command_input = f"{config_test.password}\n"
    command_str = (
        f"vault --config-path {config_test.config_path} delete {secrets_type} {name}"
    )
    _ = run_cli(
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = LocalVault(
        password=config_test.password, file=config_test.config.vault_file
    )
    assert vault.get(secrets_type, name) is None
