import pytest
from pathlib import Path

from firstpass.lib.vault import LocalVault, MemoryVault, Vault
from firstpass.lib.secrets import Secret, Password, SecretsType


@pytest.fixture()
def vault() -> Vault:
    return MemoryVault(password="password")


@pytest.mark.parametrize(
    "plaintext", [b"plaintext", b"what a string", b'{"pickles": "rule"}']
)
def test_encrypt_decrypt(plaintext: bytes, vault: Vault) -> None:
    assert vault.decrypt(vault.encrypt(plaintext)) == plaintext


@pytest.mark.parametrize(
    "secrets_type, name, secret",
    [
        (
            SecretsType.passwords,  # type: ignore
            "login1",
            Password(username="fish", password="password"),
        ),
        (
            SecretsType.passwords,  # type: ignore
            "login2",
            Password(username="jumbalaya", password="password2!xjbopajpoiabpoijweg"),
        ),
        (
            SecretsType.passwords,  # type: ignore
            "ajapdfipjwe",
            Password(username="pete", password="pebpjqefvp92!$T$!))"),
        ),
    ],
)
def test_set_get_delete(
    secrets_type: SecretsType, name: str, secret: Secret, vault: Vault
) -> None:
    vault.set(
        secrets_type,
        name,
        secret,
    )
    assert vault.get(secrets_type, name) == secret
    vault.delete(secrets_type, name)
    assert vault.get(secrets_type, name) is None


@pytest.mark.parametrize(
    "secrets_type, name, secret",
    [
        (
            SecretsType.passwords,  # type: ignore
            "pybites",
            Password(username="pybites", password="super-secret-password"),
        ),
    ],
)
def test_local_vault(
    secrets_type: SecretsType, name: str, secret: Secret, tmp_path: Path
) -> None:
    vault = LocalVault(password="password", file=tmp_path / "secrets")
    vault.set(secrets_type, name, secret)
    assert vault.get(secrets_type, name) == secret
    vault.delete(secrets_type, name)
    assert vault.get(secrets_type, name) is None
