from getpass import getpass
from pathlib import Path
from typing import Annotated, Any

import typer
from cryptography.fernet import InvalidToken
from pydantic import SecretStr, ValidationError

from firstpass import __version__, name as app_name, api_config, api_vault
from firstpass.lib.config import Config
from firstpass.lib.secrets import SecretPart, SecretsType, get_name_from_secrets_type

app = typer.Typer()
config_app = typer.Typer()
vault_app = typer.Typer()
app.add_typer(config_app, name="config")
app.add_typer(vault_app, name="vault")

state: dict[str, Any] = dict.fromkeys(
    ["config", "config_path", "config_passed_by_user"]
)
default_config_path = Path(typer.get_app_dir(app_name)) / "config.yaml"


@app.callback()
def main(
    config_path: Annotated[Path | None, typer.Option(help="Path to config")] = None,
):
    if config_path is not None and config_path != default_config_path:
        try:
            config = Config.from_yaml(config_path)
        except FileNotFoundError:
            print(f"No config exists at {config_path}")
            raise typer.Exit(1)
        except ValidationError:
            print("Provided config has invalid schema. Maybe generate a new one?")
            raise typer.Exit(1)
        state["config_path"] = config_path
        state["config"] = config
        state["config_passed_by_user"] = True
        return

    # Read the default config from disk or create a new one if it doesn't
    config_path = default_config_path
    config_path.parent.mkdir(exist_ok=True, parents=True)
    if not config_path.exists() or config_path.stat().st_size == 0:
        api_config.init(config_path)
    config = Config.from_yaml(config_path)
    state["config_path"] = config_path
    state["config"] = config
    state["config_passed_by_user"] = False


@app.command()
def version():
    print(__version__)


@config_app.command(name="init")
def config_init():
    config_path: Path = state.get("config_path")  # type: ignore
    if not state["config_passed_by_user"]:
        print(f"Default config written to {config_path}")
        typer.Exit()
    if config_path == default_config_path:
        print(
            "That's the default config path, it's initialized by default. Perhaps you want `reset`?"
        )
        raise typer.Exit()
    if config_path.exists() and config_path.stat().st_size > 0:
        overwrite = typer.confirm(
            "Config already exists there. Are you sure you want to overwrite?"
        )
        if not overwrite:
            raise typer.Abort()
        try:
            config_path.unlink()
        except FileNotFoundError:
            pass
    api_config.init(config_path)
    print(f"Default config written to {config_path}")


@config_app.command()
def reset():
    config_path: Path = state.get("config_path")  # type: ignore
    api_config.reset(config_path)


@config_app.command()
def list_keys():
    config: Config = state.get("config")  # type: ignore
    api_config.list_keys(config)


@config_app.command(name="get")
def config_get(key: str):
    config: Config = state.get("config")  # type: ignore
    api_config.get(config, key)


@config_app.command(name="set")
def config_set(key: str, value: str):
    config: Config = state.get("config")  # type: ignore
    config_path: Path = state.get("config_path")  # type: ignore
    api_config.set(config, key, value, config_path)


@vault_app.command(name="init")
def vault_init():
    config: Config = state.get("config")  # type: ignore
    if config.vault_file.exists():
        print(f"Nothing to initialize, a vault already exists at {config.vault_file}")
        raise typer.Exit()
    password = SecretStr(getpass("Please enter your password: "))
    config.vault_file.parent.mkdir(exist_ok=True, parents=True)
    config.vault_file.touch(exist_ok=True)
    api_vault.init(config, password)


@vault_app.command()
def delete():
    config: Config = state.get("config")  # type: ignore
    if not config.vault_file.exists():
        print(f"Nothing to delete, no vault file exists at {config.vault_file}")
        raise typer.Exit()
    delete = typer.confirm(
        f"Are you sure you want to delete your vault at {config.vault_file}?"
    )
    if not delete:
        raise typer.Abort()
    # TODO: Add password verification that the vault belongs to the user
    try:
        config.vault_file.unlink()
    except FileNotFoundError:
        pass
    print("Vault successfully deleted")


@vault_app.command()
def list_parts(secrets_type: SecretsType):
    secrets_name = get_name_from_secrets_type(secrets_type)
    # TODO: Update the type hint for the return value of get_name_from_secrets_type
    # it should return a BaseModel class type (but not an instance)
    # That should get rid of the mypy error
    print("\n".join(secrets_name.model_fields.keys()))  # type: ignore


@vault_app.command(name="get")
def vault_get(secrets_type: SecretsType, secret_part: SecretPart, name: str):
    config: Config = state.get("config")  # type: ignore
    secrets_name = get_name_from_secrets_type(secrets_type)
    # TODO: Update the type hint for the return value of get_name_from_secrets_type
    # it should return a BaseModel class type (but not an instance)
    # That should get rid of the mypy error
    if secret_part != SecretPart.all and secret_part not in secrets_name.model_fields:  # type: ignore
        print(f"Unsupported part for {secrets_type}. Refer to `list-parts`")
        typer.Exit()
    password = SecretStr(getpass("Please enter your password: "))
    try:
        value = api_vault.get(config, password, secrets_type, secret_part, name)
    except InvalidToken:
        print("Incorrect password")
        raise typer.Exit(1)
    print(value)
