from pydantic import SecretStr

from firstpass.lib.config import Config
from firstpass.lib.vault import LocalVault


def init(config: Config, password: SecretStr):
    if config.local and config.vault_file.exists():
        print(f"A vault already exists at {config.vault_file}")
    elif config.local:
        _ = LocalVault(password.get_secret_value(), config.vault_file)


def delete(config: Config):
    try:
        config.vault_file.unlink()
    except FileNotFoundError:
        print("Vault was already gone before we got a chance to remove it")
    print("Vault successfully deleted")
