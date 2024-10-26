import pytest
from pathlib import Path

from firstpass.vault import LocalVault, MemoryVault, Vault
from firstpass.secrets import Secret, Password, SecretsType


@pytest.fixture()
def vault() -> Vault:
    return MemoryVault(password="password")


@pytest.mark.parametrize(
    "plaintext", [b"plaintext", b"what a string", b'{"pickles": "rule"}']
)
def test_encrypt_decrypt(plaintext: bytes, vault: Vault) -> None:
    assert vault.decrypt(vault.encrypt(plaintext)) == plaintext


@pytest.mark.parametrize(
    "name, secret, secrets_type",
    [
        (
            "login1",
            Password(username="fish", password="password"),
            SecretsType.passwords,
        ),
        (
            "login2",
            Password(username="jumbalaya", password="password2!xjbopajpoiabpoijweg"),
            SecretsType.passwords,
        ),
        (
            "ajapdfipjwe",
            Password(username="pete", password="pebpjqefvp92!$T$!))"),
            SecretsType.passwords,
        ),
    ],
)
def test_set_get_delete(
    name: str, secret: Secret, secrets_type: SecretsType, vault: Vault
) -> None:
    vault.set(name, secret, secrets_type)
    assert vault.get(name, secrets_type) == secret
    vault.delete(name, secrets_type)
    assert vault.get(name, secrets_type) is None


@pytest.mark.parametrize(
    "name, secret, secrets_type",
    [
        (
            "pybites",
            Password(username="pybites", password="super-secret-password"),
            SecretsType.passwords,
        ),
    ],
)
def test_local_vault(
    name: str, secret: Secret, secrets_type: SecretsType, tmp_path: Path
) -> None:
    vault = LocalVault(password="password", file=tmp_path / "secrets")
    vault.set(name, secret, secrets_type)
    assert vault.get(name, secrets_type) == secret
    vault.delete(name, secrets_type)
    assert vault.get(name, secrets_type) is None
