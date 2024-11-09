from firstpass.lib.config import Config
from firstpass.lib.secrets import Secret, SecretPart, SecretsType
from firstpass.lib.vault import LocalVault


def init(config: Config, password: str):
    LocalVault(password, config.vault_file)


def new(
    config: Config, password: str, secrets_type: SecretsType, name: str, secret: Secret
) -> None:
    vault = LocalVault(password, config.vault_file)
    vault.set(secrets_type, name, secret)


def get(
    config: Config,
    password: str,
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
) -> Secret | None:
    vault = LocalVault(password, config.vault_file)
    secret = vault.get(secrets_type, name)
    if secret is None:
        return None
    if secret_part == SecretPart.all:
        return secret
    return getattr(secret, secret_part)


def set(
    config: Config,
    password: str,
    secrets_type: SecretsType,
    name: str,
    secret_part: SecretPart,
    value: str,
) -> None:
    vault = LocalVault(password, config.vault_file)
    secret = vault.get(secrets_type, name)
    if secret is None:
        return
    setattr(secret, secret_part, value)
    vault.set(secrets_type, name, secret)


def delete(config: Config, password: str, secrets_type: SecretsType, name: str) -> None:
    vault = LocalVault(password, config.vault_file)
    vault.delete(secrets_type, name)
