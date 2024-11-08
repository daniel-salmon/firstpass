from pydantic import SecretStr

from firstpass.lib.config import Config
from firstpass.lib.secrets import Secret, SecretPart, SecretsType
from firstpass.lib.vault import LocalVault


def init(config: Config, password: SecretStr):
    LocalVault(password.get_secret_value(), config.vault_file)


def get(
    config: Config,
    password: SecretStr,
    secrets_type: SecretsType,
    secret_part: SecretPart,
    name: str,
) -> Secret | None:
    vault = LocalVault(password.get_secret_value(), config.vault_file)
    secret = vault.get(secrets_type, name)
    if secret is None:
        return None
    if secret_part == SecretPart.all:
        return secret
    return getattr(secret, secret_part)
