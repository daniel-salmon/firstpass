from pathlib import Path
from typing import Annotated, TypedDict

import pyperclip
import typer
from pydantic import SecretStr, ValidationError

from firstpass import __version__, name as app_name, api_config
from firstpass.lib.config import Config
from firstpass.lib.secrets import SecretPart, SecretsType, get_name_from_secrets_type
from firstpass.lib.vault import LocalVault, Vault

app = typer.Typer()
config_app = typer.Typer()
vault_app = typer.Typer()
app.add_typer(config_app, name="config")
app.add_typer(vault_app, name="vault")

State = TypedDict(
    "State",
    {
        "config": Config | None,
        "config_path": Path | None,
        "config_passed_by_user": bool,
        "vault": Vault | None,
    },
)
state: State = {
    "config": None,
    "config_path": None,
    "config_passed_by_user": False,
    "vault": None,
}
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


def password_check(password: str) -> str:
    config = state.get("config")
    assert config is not None
    if not config.vault_file.exists():
        print(f"No vault exists at {config.vault_file}. Create one with vault init")
        raise typer.Exit()
    vault = LocalVault(password, config.vault_file)
    if not vault.can_open():
        raise typer.BadParameter("Invalid password")
    state["vault"] = vault
    return password


@app.command()
def version():
    print(__version__)


@config_app.command(name="init")
def config_init():
    config_path = state.get("config_path")
    assert config_path is not None
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
    config_path = state.get("config_path")
    assert config_path is not None
    api_config.reset(config_path)


@config_app.command()
def list_keys():
    config = state.get("config")
    assert config is not None
    api_config.list_keys(config)


@config_app.command(name="get")
def config_get(key: str):
    config = state.get("config")
    assert config is not None
    api_config.get(config, key)


@config_app.command(name="set")
def config_set(key: str, value: str):
    config = state.get("config")
    config_path = state.get("config_path")
    assert config is not None and config_path is not None
    api_config.set(config, key, value, config_path)


@vault_app.command(name="list-parts")
def vault_list_parts(secrets_type: SecretsType):
    secrets_name = get_name_from_secrets_type(secrets_type)
    print("\n".join(secrets_name.model_fields.keys()))


@vault_app.command(name="init")
def vault_init():
    config = state.get("config")
    assert config is not None
    if config.vault_file.exists():
        print(f"Nothing to initialize, a vault already exists at {config.vault_file}")
        raise typer.Exit()
    password1 = typer.prompt(
        "Please enter your new firstpass password", hide_input=True
    )
    password2 = typer.prompt(
        "Please re-entery your new firstpass password", hide_input=True
    )
    if password1 != password2:
        print("Passwords do not match, try again")
        raise typer.Abort()
    config.vault_file.parent.mkdir(exist_ok=True, parents=True)
    config.vault_file.touch(exist_ok=True)
    LocalVault(password1, config.vault_file)


@vault_app.command(name="remove")
def vault_remove(
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    config = state.get("config")
    assert config is not None
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
    vault = state.get("vault")
    assert vault is not None
    secrets_name = get_name_from_secrets_type(secrets_type)
    print(f"Let's create a new vault entry for {secrets_type}")
    name = typer.prompt("What's the name of this entry?")
    fields = dict.fromkeys(secrets_name.model_fields.keys())
    if "password" in fields:
        password1 = typer.prompt("Enter the password", hide_input=True)
        password2 = typer.prompt("Reenter the password", hide_input=True)
        if password1 != password2:
            print("Passwords do not match!")
            raise typer.Abort()
        fields["password"] = password1
    for field in secrets_name.model_fields.keys():
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
    vault.set(secrets_type, name, secret)


@vault_app.command(name="list-names")
def vault_list_names(
    secrets_type: SecretsType,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    vault = state.get("vault")
    assert vault is not None
    print("\n".join(vault.list_names(secrets_type)))


@vault_app.command(name="get")
def vault_get(
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
    show: bool = False,
    copy: bool = False,
):
    vault = state.get("vault")
    assert vault is not None
    secrets_name = get_name_from_secrets_type(secrets_type)
    if secret_part != SecretPart.all and secret_part not in secrets_name.model_fields:
        print(f"Unsupported part for {secrets_type}. Refer to `list-parts`")
        raise typer.Exit()
    if (secret := vault.get(secrets_type, name)) is None:
        print(f"No secret called {name} exists in your vault under type {secrets_type}")
        raise typer.Exit()
    if secret_part == SecretPart.all:
        print(secret)
        raise typer.Exit()
    value: str | SecretStr = getattr(secret, secret_part)
    if copy:
        if isinstance(value, SecretStr):
            pyperclip.copy(value.get_secret_value())
        else:
            pyperclip.copy(value)
    if show and secret_part == SecretPart.password:
        assert isinstance(value, SecretStr)
        print(value.get_secret_value())
        raise typer.Exit()
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
    vault = state.get("vault")
    assert vault is not None
    secrets_name = get_name_from_secrets_type(secrets_type)
    if secret_part == SecretPart.all:
        print(
            "Can't set {SecretPart.all} from the command line. Please set parts individually."
        )
        raise typer.Exit()
    if secret_part not in secrets_name.model_fields:
        print(f"Unsupported part for {secrets_type}. Refer to `list-parts`")
        raise typer.Exit()
    if (secret := vault.get(secrets_type, name)) is None:
        print(f"No secret called {name} exists in your vault under type {secrets_type}")
        raise typer.Exit()
    setattr(secret, secret_part, value)
    vault.set(secrets_type, name, secret)


@vault_app.command(name="delete")
def vault_delete(
    secrets_type: SecretsType,
    name: str,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    vault = state.get("vault")
    assert vault is not None
    vault.delete(secrets_type, name)
