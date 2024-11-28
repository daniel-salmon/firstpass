import pytest
from typer.testing import CliRunner

from firstpass.cli import app
from firstpass.utils import CloudVault

from . import run_cli

runner = CliRunner()


@pytest.mark.parametrize(
    "cloud_test_str, command_input, want_exit_code",
    [
        ("default_cloud_test_user_does_not_exist", "password\npassword\ny\n", 0),
        (
            "default_cloud_test_user_does_not_exist",
            "password\ndifferentpassword\ny\n",
            1,
        ),
        ("default_cloud_test_user_exists", "password\npassword\ny\n", 1),
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
