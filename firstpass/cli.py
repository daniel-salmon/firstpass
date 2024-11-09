from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError

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

    # Read the default config from disk or create a new one if it doesn't exist
    config_path = default_config_path
    config_path.parent.mkdir(exist_ok=True, parents=True)
    if not config_path.exists() or config_path.stat().st_size == 0:
        api_config.init(config_path)
    config = Config.from_yaml(config_path)
    state["config_path"] = config_path
    state["config"] = config
    state["config_passed_by_user"] = False


# TODO: Perhaps refactor this to set the vault object as
# part of the application state, that way you don't have to
# make another one later.
# This will also allow the api_vault functions to receive a Vault
# object directly, simplify the interface there, since all the logic
# about deciding if the vault is cloud-based or local will be taken
# care of centrally here.
def password_check(password: str) -> str:
    config: Config = state.get("config")  # type: ignore
    vault_auth = api_vault.authorize(config, password)
    if not vault_auth.is_authorized:
        raise typer.BadParameter("Invalid password")
    state["token"] = vault_auth.token
    return password


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


@vault_app.command(name="list-parts")
def vault_list_parts(secrets_type: SecretsType):
    secrets_name = get_name_from_secrets_type(secrets_type)
    # TODO: Update the type hint for the return value of get_name_from_secrets_type
    # it should return a BaseModel class type (but not an instance)
    # That should get rid of the mypy error
    print("\n".join(secrets_name.model_fields.keys()))  # type: ignore


@vault_app.command(name="init")
def vault_init():
    config: Config = state.get("config")  # type: ignore
    if config.vault_file.exists():
        print(f"Nothing to initialize, a vault already exists at {config.vault_file}")
        raise typer.Exit()
    password = typer.prompt("Please enter your new firstpass password", hide_input=True)
    config.vault_file.parent.mkdir(exist_ok=True, parents=True)
    config.vault_file.touch(exist_ok=True)
    api_vault.init(config, password)


@vault_app.command(name="remove")
def vault_remove(
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    config: Config = state.get("config")  # type: ignore
    if not config.vault_file.exists():
        print(f"Nothing to delete, no vault file exists at {config.vault_file}")
        raise typer.Exit()
    delete = typer.confirm(
        f"Are you sure you want to delete your vault at {config.vault_file}?"
    )
    if not delete:
        raise typer.Abort()
    try:
        config.vault_file.unlink()
    except FileNotFoundError:
        pass
    print("Vault successfully removed")


@vault_app.command(name="new")
def vault_new(
    secrets_type: SecretsType,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    config: Config = state.get("config")  # type: ignore
    secrets_name = get_name_from_secrets_type(secrets_type)
    print(f"Let's create a new vault entry for {secrets_type}")
    name = typer.prompt("What's the name of this entry?")
    fields = dict.fromkeys(secrets_name.model_fields.keys())  # type: ignore
    if "password" in fields:
        password1 = typer.prompt("Enter the password", hide_input=True)
        password2 = typer.prompt("Reenter the password", hide_input=True)
        if password1 != password2:
            print("Passwords do not match!")
            raise typer.Abort()
        fields["password"] = password1
    for field in secrets_name.model_fields.keys():  # type: ignore
        if field == "password":
            continue
        fields[field] = typer.prompt(f"Enter the {field}")
    try:
        secret = secrets_name(**fields)
    except ValidationError:
        # TODO: Give a better explanation
        # Also, since all of these fields should be raw strings, perhaps this can't even happen?
        print("One or more of your secret values can't be validated")
        raise typer.Abort()
    api_vault.new(config, password, secrets_type, name, secret)


@vault_app.command(name="list-names")
def vault_list_names(
    secrets_type: SecretsType,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    config: Config = state.get("config")  # type: ignore
    names = api_vault.list_names(config, password, secrets_type)
    print("\n".join(names))


@vault_app.command(name="get")
def vault_get(
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    config: Config = state.get("config")  # type: ignore
    secrets_name = get_name_from_secrets_type(secrets_type)
    # TODO: Update the type hint for the return value of get_name_from_secrets_type
    # it should return a BaseModel class type (but not an instance)
    # That should get rid of the mypy error
    if secret_part != SecretPart.all and secret_part not in secrets_name.model_fields:  # type: ignore
        print(f"Unsupported part for {secrets_type}. Refer to `list-parts`")
        raise typer.Exit()
    value = api_vault.get(config, password, secrets_type, name, secret_part)
    print(value)


@vault_app.command(name="set")
def vault_set(
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
    value: str,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    config: Config = state.get("config")  # type: ignore
    secrets_name = get_name_from_secrets_type(secrets_type)
    if secret_part == SecretPart.all:
        print(
            "Can't set {SecretPart.all} from the command line. Please set parts individually."
        )
        raise typer.Exit()
    if secret_part not in secrets_name.model_fields:  # type: ignore
        print(f"Unsupported part for {secrets_type}. Refer to `list-parts`")
        raise typer.Exit()
    # TODO: Should there be a check / return in case no such secret exists?
    api_vault.set(config, password, secrets_type, name, secret_part, value)


@vault_app.command(name="delete")
def vault_delete(
    secrets_type: SecretsType,
    name: str,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    config: Config = state.get("config")  # type: ignore
    api_vault.delete(config, password, secrets_type, name)
