from pathlib import Path
from typing import Annotated, Any

import typer

from firstpass import __version__, name as app_name, api_config
from firstpass.lib.config import Config

app = typer.Typer()
config_app = typer.Typer()
app.add_typer(config_app, name="config")

state: dict[str, Any] = {}


@app.callback()
def main(
    config_path: Annotated[Path | None, typer.Option(help="Path to config")] = None,
):
    if config_path is None:
        config_path = Path(typer.get_app_dir(app_name))
        config_path.mkdir(exist_ok=True, parents=True)
        config_path /= "config.yaml"
    state["config_path"] = config_path
    if config_path.exists():
        state["config"] = Config.from_yaml(config_path)
        return
    print(f"Initialising firstpass config at {config_path}")
    config = Config()
    config.to_yaml(config_path)
    state["config"] = config


@app.command()
def version():
    print(__version__)


@app.command()
def echo(value: str):
    print(value)


@config_app.command()
def list_keys():
    config: Config = state.get("config")  # type: ignore
    api_config.list_keys(config)


@config_app.command()
def get(key: str):
    config: Config = state.get("config")  # type: ignore
    api_config.get(config, key)


@config_app.command()
def set(key: str, value: str):
    config: Config = state.get("config")  # type: ignore
    config_path: Path = state.get("config_path")  # type: ignore
    api_config.set(config, key, value, config_path)
