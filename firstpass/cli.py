from pathlib import Path
from typing import Annotated, TypedDict

import pyperclip
import typer
from pydantic import SecretStr, ValidationError

from . import __version__
from . import name as app_name
from .utils import (
    CloudVault,
    Config,
    ConfigKeyDoesNotExistError,
    ConfigValidationError,
    LocalVault,
    SecretPart,
    Secrets,
    SecretsType,
    Vault,
    VaultInvalidUsernameOrPasswordError,
    VaultUnavailableError,
    VaultUsernameAlreadyExistsError,
    get_name_from_secrets_type,
    update_config,
)

State = TypedDict(
    "State",
    {
        "config": Config | None,
        "config_path": Path | None,
        "vault": Vault | None,
    },
)
state: State = {
    "config": None,
    "config_path": None,
    "vault": None,
}
default_config_path = Path(typer.get_app_dir(app_name)) / "config.yaml"


def load_config(
    config_path: Annotated[Path | None, typer.Option(help="Path to config")] = None,
):
    if config_path is None:
        config_path = default_config_path
    try:
        config = Config.from_yaml(config_path)
    except FileNotFoundError:
        print(
            f"No config exists at {config_path}. Maybe generate a new one with `init config`?"
        )
        raise typer.Exit(1)
    except ValidationError:
        print(
            "Provided config has invalid schema. Maybe generate a new one with `init config`?"
        )
        raise typer.Exit(1)
    state["config_path"] = config_path
    state["config"] = config
    return


def password_check(password: str) -> str:
    config = state.get("config")
    if config is None:
        raise AssertionError("config is None")
    vault: Vault
    if config.local:
        if not config.vault_file.exists():
            print(f"No vault exists at {config.vault_file}. Create one with vault init")
            raise typer.Exit(1)
        vault = LocalVault(password, config.vault_file)
        if not vault.can_open():
            raise typer.BadParameter("Invalid password")
    else:
        try:
            vault = CloudVault(
                username=config.username,
                password=password,
                host=config.cloud_host,
                access_token=None,
            )
        except VaultInvalidUsernameOrPasswordError:
            print(
                "Invalid username or password. Have you initialized a vault before? If not run `vault init`. Otherwise, this is likely a problem with your password."
            )
            raise typer.Exit(1)
        except VaultUnavailableError:
            print("There seems to be an issue, try that again")
            raise typer.Exit(1)
    state["vault"] = vault
    return password


app = typer.Typer()
init_app = typer.Typer()
config_app = typer.Typer(callback=load_config)
vault_app = typer.Typer(callback=load_config)
app.add_typer(init_app, name="init", help="Initialize a new config.")
app.add_typer(config_app, name="config", help="Manage a config.")
app.add_typer(vault_app, name="vault", help="Manage your vault.")


@app.command()
def version():
    print(__version__)


@init_app.command(name="config")
def init_config(
    config_path: Annotated[Path | None, typer.Option(help="Path to config")] = None,
):
    """
    Initialize a new config.
    """
    if config_path is None:
        config_path = default_config_path
    if config_path.exists() and config_path.stat().st_size > 0:
        overwrite = typer.confirm(
            "Config already exists there. Are you sure you want to overwrite? This will reset the config to default settings."
        )
        if not overwrite:
            raise typer.Abort()
        try:
            config_path.unlink()
        except FileNotFoundError:
            pass
    config = Config()
    config.to_yaml(config_path)
    print(f"Default config written to {config_path}")


@config_app.command(name="list-keys")
def config_list_keys():
    """
    List options available to customize in your config.
    """
    config = state.get("config")
    if config is None:
        raise AssertionError("config is None")
    print("\n".join(sorted(config.list_keys())))


@config_app.command(name="get")
def config_get(key: str):
    """
    Get an option from your config.
    """
    config = state.get("config")
    if config is None:
        raise AssertionError("config is None")
    try:
        value = getattr(config, key)
    except AttributeError:
        print(f"{key} is not a config setting")
        raise typer.Exit(1)
    print(f"{key}={value}")


@config_app.command(name="set")
def config_set(key: str, value: str):
    """
    Set an option in your config.
    """
    config = state.get("config")
    config_path = state.get("config_path")
    if config is None:
        raise AssertionError("config is None")
    if config_path is None:
        raise AssertionError("config_path is None")
    try:
        updated_config = update_config(config, key, value)
    except ConfigKeyDoesNotExistError:
        print(f"{key} is not a config setting")
        raise typer.Exit(1)
    except ConfigValidationError:
        print(
            f"Provided value does not match schema. {key} requires type compatible with {Config.model_fields[key].annotation}"
        )
        raise typer.Exit(1)
    updated_config.to_yaml(config_path)


@vault_app.command(name="list-parts")
def vault_list_parts(secrets_type: SecretsType):
    """
    List the parts of the given type of secret.
    """
    secrets_name = get_name_from_secrets_type(secrets_type)
    print("\n".join(sorted(secrets_name.list_parts())))


@vault_app.command(name="init")
def vault_init():
    """
    Initialize a new vault.

    You should only run this the first time you want to create a vault after
    initializing a new config for your profile.
    """
    config = state.get("config")
    if config is None:
        raise AssertionError("config is None")
    if config.local and config.vault_file.exists():
        print(f"Nothing to initialize, a vault already exists at {config.vault_file}")
        raise typer.Exit(1)
    if not config.local:
        username_correct = typer.confirm(
            f"Please confirm your username: {config.username}"
        )
        if not username_correct:
            print(
                "Please set your username with `config set username <desired username>`"
            )
            raise typer.Abort()
    password1 = typer.prompt(
        "Please enter your new firstpass password", hide_input=True
    )
    password2 = typer.prompt(
        "Please re-enter your new firstpass password", hide_input=True
    )
    if password1 != password2:
        print("Passwords do not match, try again")
        raise typer.Abort()
    password = password1
    if config.local:
        config.vault_file.parent.mkdir(exist_ok=True, parents=True)
        config.vault_file.touch(exist_ok=True)
        LocalVault(password, config.vault_file)
        print("Successfully initialized vault!")
        raise typer.Exit()
    try:
        token = CloudVault.create_new_user(
            username=config.username, password=password1, host=config.cloud_host
        )
        vault = CloudVault(
            username=config.username,
            password=password,
            host=config.cloud_host,
            access_token=token.access_token,
        )
        vault.write_secrets(Secrets())
    except VaultUsernameAlreadyExistsError:
        print(
            "Username already exists. Please set a new username with `config set username <desired username>`"
        )
        raise typer.Exit(1)
    except VaultUnavailableError:
        print("There seems to be an issue, try that again")
        raise typer.Exit(1)
    print("Successfully intialized vault!")


@vault_app.command(name="remove")
def vault_remove(
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    """
    Remove your vault.
    """
    config, vault = state.get("config"), state.get("vault")
    if config is None:
        raise AssertionError("config is None")
    if vault is None:
        raise AssertionError("vault is None")
    delete = typer.confirm(
        f"Are you sure you want to delete your vault {'at ' + str(config.vault_file) if config.local else ''}?"
    )
    if not delete:
        raise typer.Abort()
    try:
        vault.remove()
    except VaultUnavailableError:
        print("There seems to be an issue, try that again")
        raise typer.Exit(1)
    print("Vault successfully removed")


@vault_app.command(name="new")
def vault_new(
    secrets_type: SecretsType,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    """
    Create a new secret / entry for your vault.
    """
    vault = state.get("vault")
    if vault is None:
        raise AssertionError("vault is None")
    secrets_name = get_name_from_secrets_type(secrets_type)
    print(f"Let's create a new vault entry for {secrets_type}")
    name = typer.prompt("What's the name of this entry?")
    if vault.get(secrets_type, name) is not None:
        print(
            f"A vault entry with name {name} already exists. Please choose a new name or update the entry already there"
        )
        raise typer.Abort()
    fields = dict.fromkeys(secrets_name.model_fields.keys())
    if "password" in fields:
        while True:
            password1 = typer.prompt("Enter the password", hide_input=True)
            password2 = typer.prompt("Reenter the password", hide_input=True)
            if password1 == password2:
                break
            print("Passwords do not match!")
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
    """
    List the names of all of your secrets.
    """
    vault = state.get("vault")
    if vault is None:
        raise AssertionError("vault is None")
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
    """
    Get a secret by name from your vault.
    """
    vault = state.get("vault")
    if vault is None:
        raise AssertionError("vault is None")
    secrets_name = get_name_from_secrets_type(secrets_type)
    if secret_part != SecretPart.all and secret_part not in secrets_name.model_fields:
        print(f"Unsupported part for {secrets_type}. Refer to `list-parts`")
        raise typer.Exit(1)
    if (secret := vault.get(secrets_type, name)) is None:
        print(f"No secret called {name} exists in your vault under type {secrets_type}")
        raise typer.Exit(1)
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
        if not isinstance(value, SecretStr):
            raise AssertionError("value is not of type SecretStr")
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
    """
    Set the value for a secret.
    """
    vault = state.get("vault")
    if vault is None:
        raise AssertionError("vault is None")
    secrets_name = get_name_from_secrets_type(secrets_type)
    if secret_part == SecretPart.all:
        print(
            "Can't set {SecretPart.all} from the command line. Please set parts individually."
        )
        raise typer.Exit(1)
    if secret_part not in secrets_name.model_fields:
        print(f"Unsupported part for {secrets_type}. Refer to `list-parts`")
        raise typer.Exit(1)
    if (secret := vault.get(secrets_type, name)) is None:
        print(f"No secret called {name} exists in your vault under type {secrets_type}")
        raise typer.Exit(1)
    secret_dict = secret.dict()
    secret_dict[secret_part] = value
    updated_secret = secrets_name(**secret_dict)
    vault.set(secrets_type, name, updated_secret)


@vault_app.command(name="delete")
def vault_delete(
    secrets_type: SecretsType,
    name: str,
    password: Annotated[
        str, typer.Option(prompt=True, hide_input=True, callback=password_check)
    ],
):
    """
    Delete a secret from your vault.
    """
    vault = state.get("vault")
    if vault is None:
        raise AssertionError("vault is None")
    vault.delete(secrets_type, name)
