from pydantic import SecretStr

from firstpass.lib.config import Config
from firstpass.lib.secrets import Secret, SecretsType
from firstpass.lib.vault import LocalVault


def init(config: Config, password: SecretStr):
    LocalVault(password.get_secret_value(), config.vault_file)


def get(
    config: Config, password: SecretStr, secrets_type: SecretsType, name: str
) -> Secret | None:
    vault = LocalVault(password.get_secret_value(), config.vault_file)
    return vault.get(secrets_type, name)
