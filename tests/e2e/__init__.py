import shlex
from dataclasses import dataclass
from pathlib import Path

from click.testing import Result
from typer import Typer
from typer.testing import CliRunner

from firstpass.utils import Config


@dataclass
class ConfigTest:
    config: Config | None
    config_path: Path
    password: str


def run_cli(
    *,
    runner: CliRunner,
    app: Typer,
    command_str: str,
    command_input: str | None,
    want_exit_code: int,
) -> Result:
    command = shlex.split(command_str)
    result = runner.invoke(app, command, input=command_input)
    assert result.exit_code == want_exit_code
    return result
