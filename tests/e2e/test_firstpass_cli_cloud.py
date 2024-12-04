from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from firstpass.cli import app
from firstpass.utils import (
    CloudVault,
    Password,
    Secret,
    SecretPart,
    SecretsType,
    VaultInvalidUsernameOrPasswordError,
)

from . import run_cli

runner = CliRunner()


@pytest.mark.parametrize(
    "cloud_test_str, command_input, want_exit_code",
    [
        ("default_cloud_test_user_does_not_exist", "y\npassword\npassword\n", 0),
        ("default_cloud_test_user_does_not_exist", "n\npassword\npassword\n", 1),
        (
            "default_cloud_test_user_does_not_exist",
            "y\npassword\ndifferentpassword\n",
            1,
        ),
        ("default_cloud_test_user_exists_empty_vault", "y\npassword\npassword\n", 1),
    ],
)
def test_vault_init(
    cloud_test_str: str,
    command_input: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
) -> None:
    cloud_test = request.getfixturevalue(cloud_test_str)
    command_str = f"vault --config-path {cloud_test.config_path} init"
    _ = run_cli(
        runner=runner,
        app=app,
        command_str=command_str,
        command_input=command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = CloudVault(
        username=cloud_test.config.username,
        password=cloud_test.password,
        host=cloud_test.config.cloud_host,
        access_token=None,
    )
    assert vault.can_open()


@pytest.mark.parametrize(
    "cloud_test_str, command_input, want_exit_code",
    [
        ("default_cloud_test_user_does_not_exist", "password\ny", 1),
        ("default_cloud_test_user_exists_empty_vault", "wrongpassword\ny", 1),
        ("default_cloud_test_user_exists_empty_vault", "password\nn", 1),
        ("default_cloud_test_user_exists_empty_vault", "password\ny", 0),
    ],
)
def test_vault_remove(
    cloud_test_str: str,
    command_input: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
) -> None:
    cloud_test = request.getfixturevalue(cloud_test_str)
    command_str = f"vault --config-path {cloud_test.config_path} remove"
    _ = run_cli(
        runner=runner,
        app=app,
        command_str=command_str,
        command_input=command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    # Confirm the vault no longer exists, which would mean the username / password
    # combination should no longer work
    with pytest.raises(VaultInvalidUsernameOrPasswordError):
        _ = CloudVault(
            username=cloud_test.config.username,
            password=cloud_test.password,
            host=cloud_test.config.cloud_host,
            access_token=None,
        )


@pytest.mark.parametrize(
    "cloud_test_str, secrets_type, name, want_secret, command_input, want_exit_code",
    [
        (
            "default_cloud_test_user_exists_empty_vault",
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
            "default_cloud_test_user_exists_empty_vault",
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
            "default_cloud_test_user_exists_empty_vault",
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
        (
            "default_cloud_test_user_exists_pizza_vault",
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
            "default_cloud_test_user_does_not_exist",
            SecretsType.passwords,
            "pizza",
            Password(
                label="PyBites",
                notes="notes",
                username="daniel",
                password=SecretStr("password"),
            ),
            "",
            1,
        ),
    ],
)
def test_vault_new(
    cloud_test_str: str,
    secrets_type: SecretsType,
    name: str,
    want_secret: Secret,
    command_input: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    cloud_test = request.getfixturevalue(cloud_test_str)
    passworded_command_input = "\n".join((cloud_test.password, command_input))
    command_str = f"vault --config-path {cloud_test.config_path} new {secrets_type}"
    _ = run_cli(
        runner=runner,
        app=app,
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = CloudVault(
        username=cloud_test.config.username,
        password=cloud_test.password,
        host=cloud_test.config.cloud_host,
        access_token=None,
    )
    got_secret = vault.get(secrets_type, name)
    assert got_secret == want_secret


@pytest.mark.parametrize(
    "cloud_test_str, secrets_type, want_exit_code",
    [
        ("default_cloud_test_user_does_not_exist", SecretsType.passwords, 1),
        ("default_cloud_test_user_exists_empty_vault", SecretsType.passwords, 0),
        ("default_cloud_test_user_exists_pizza_vault", SecretsType.passwords, 0),
    ],
)
def test_vault_list_names(
    cloud_test_str: str,
    secrets_type: SecretsType,
    want_exit_code: int,
    request: pytest.FixtureRequest,
) -> None:
    cloud_test = request.getfixturevalue(cloud_test_str)
    passworded_command_input = f"{cloud_test.password}\n"
    command_str = (
        f"vault --config-path {cloud_test.config_path} list-names {secrets_type}"
    )
    result = run_cli(
        runner=runner,
        app=app,
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = CloudVault(
        username=cloud_test.config.username,
        password=cloud_test.password,
        host=cloud_test.config.cloud_host,
        access_token=None,
    )
    want_names = vault.list_names(secrets_type)
    output = result.stdout.strip().splitlines()
    # Remove the Password: prompt
    output.pop(0)
    assert len(output) == len(want_names)
    assert set(output) == want_names


@pytest.mark.parametrize(
    "cloud_test_str, secrets_type, name, secret_part, show, copy, want_exit_code",
    [
        (
            "default_cloud_test_user_does_not_exist",
            SecretsType.passwords,
            "name_that_doesnt_exist",
            SecretPart.all,
            True,
            True,
            1,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "name_that_doesnt_exist",
            SecretPart.all,
            True,
            True,
            1,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.all,
            True,
            True,
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.all,
            True,
            False,
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.username,
            True,
            True,
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.username,
            False,
            True,
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.username,
            False,
            False,
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.password,
            True,
            True,
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.password,
            False,
            True,
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.password,
            True,
            False,
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.password,
            False,
            False,
            0,
        ),
        (
            "default_cloud_test_user_exists_empty_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.password,
            True,
            True,
            1,
        ),
    ],
)
@patch("firstpass.cli.pyperclip.copy")
def test_vault_get(
    pyperclip_mock: MagicMock,
    cloud_test_str: str,
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
    show: bool,
    copy: bool,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    cloud_test = request.getfixturevalue(cloud_test_str)
    passworded_command_input = f"{cloud_test.password}\n"
    command_str = f"vault --config-path {cloud_test.config_path} get {secrets_type} {name} {secret_part} {'--show' if show else ''} {'--copy' if copy else ''}"
    result = run_cli(
        runner=runner,
        app=app,
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = CloudVault(
        username=cloud_test.config.username,
        password=cloud_test.password,
        host=cloud_test.config.cloud_host,
        access_token=None,
    )
    output = result.stdout.strip().splitlines()
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
    "cloud_test_str, secrets_type, name, secret_part, value, want_exit_code",
    [
        (
            "default_cloud_test_user_does_not_exist",
            SecretsType.passwords,
            "pizza",
            SecretPart.username,
            "pepperoni",
            1,
        ),
        (
            "default_cloud_test_user_exists_empty_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.username,
            "pepperoni",
            1,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "name_that_doesnt_exist",
            SecretPart.username,
            "pepperoni",
            1,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.username,
            "pepperoni",
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.label,
            "meatball",
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.notes,
            "Chicago style",
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            SecretPart.password,
            "new password",
            0,
        ),
    ],
)
def test_vault_set(
    cloud_test_str: str,
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
    value: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    cloud_test = request.getfixturevalue(cloud_test_str)
    passworded_command_input = f"{cloud_test.password}\n"
    command_str = f"vault --config-path {cloud_test.config_path} set {secrets_type} {name} {secret_part} '{value}'"
    _ = run_cli(
        runner=runner,
        app=app,
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = CloudVault(
        username=cloud_test.config.username,
        password=cloud_test.password,
        host=cloud_test.config.cloud_host,
        access_token=None,
    )
    if secret_part == SecretPart.password:
        assert (
            getattr(vault.get(secrets_type, name), secret_part)
        ).get_secret_value() == value
        return
    assert getattr(vault.get(secrets_type, name), secret_part) == value


@pytest.mark.parametrize(
    "cloud_test_str, secrets_type, name, want_exit_code",
    [
        ("default_cloud_test_user_does_not_exist", SecretsType.passwords, "pizza", 1),
        (
            "default_cloud_test_user_exists_empty_vault",
            SecretsType.passwords,
            "pizza",
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pizza",
            0,
        ),
        (
            "default_cloud_test_user_exists_pizza_vault",
            SecretsType.passwords,
            "pepperoni",
            0,
        ),
    ],
)
def test_vault_delete(
    cloud_test_str: str,
    secrets_type: SecretsType,
    name: str,
    want_exit_code: int,
    request: pytest.FixtureRequest,
):
    cloud_test = request.getfixturevalue(cloud_test_str)
    passworded_command_input = f"{cloud_test.password}\n"
    command_str = (
        f"vault --config-path {cloud_test.config_path} delete {secrets_type} {name}"
    )
    _ = run_cli(
        runner=runner,
        app=app,
        command_str=command_str,
        command_input=passworded_command_input,
        want_exit_code=want_exit_code,
    )
    if want_exit_code != 0:
        return
    vault = CloudVault(
        username=cloud_test.config.username,
        password=cloud_test.password,
        host=cloud_test.config.cloud_host,
        access_token=None,
    )
    assert vault.get(secrets_type, name) is None
