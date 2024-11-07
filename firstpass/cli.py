from pathlib import Path
from typing import Annotated, Any

import typer

from firstpass import __version__, name as app_name
from firstpass.lib.config import Config

app = typer.Typer()
config_app = typer.Typer()
app.add_typer(config_app, name="config")


state: dict[str, Any] = {}
config: Config = Config()


@app.callback()
def main(
    config_path: Annotated[Path | None, typer.Option(help="Path to config")] = None,
):
    global config
    if config_path is None:
        config_path = Path(typer.get_app_dir(app_name))
        config_path.mkdir(exist_ok=True, parents=True)
        config_path /= "config.yaml"
    state["config_path"] = config_path
    if config_path.exists():
        config = Config.from_yaml(config_path)
        return
    print(f"Initialising firstpass config at {config_path}")
    config.to_yaml(config_path)


@app.command()
def version():
    print(__version__)


@app.command()
def echo(value: str):
    print(value)


@config_app.command()
def list_keys():
    print("\n".join(config.model_dump().keys()))


@config_app.command()
def get(key: str):
    try:
        value = getattr(config, key)
    except AttributeError:
        print(f"{key} is not a setting")
        return
    print(f"{key} = {value}")


@config_app.command()
def set(key: str, value: str):
    global config
    if not hasattr(config, key):
        print(f"{key} is not a setting")
        return
    config_dict = config.model_dump()
    config_dict[key] = value
    config = Config(**config_dict)
    config.to_yaml(state["config_path"])
