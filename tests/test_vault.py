import pytest
from pathlib import Path

from firstpass.vault import LocalVault, MemoryVault, Vault


@pytest.fixture()
def vault() -> Vault:
    return MemoryVault(password="password")


@pytest.mark.parametrize(
    "plaintext", [b"plaintext", b"what a string", b'{"pickles": "rule"}']
)
def test_encrypt_decrypt(plaintext: bytes, vault: Vault) -> None:
    assert vault.decrypt(vault.encrypt(plaintext)) == plaintext


@pytest.mark.parametrize(
    "name, value",
    [
        ("login1", "password1"),
        ("login2", "password2!xjbopajpoiabpoijweg"),
        ("ajapdfipjwe", "pebpjqefvp92!$T$!))"),
    ],
)
def test_set_get_delete(name: str, value: str, vault: Vault) -> None:
    vault.set(name, value)
    assert vault.get(name) == value
    vault.delete(name)
    assert vault.get(name) is None


@pytest.mark.parametrize(
    "name, value",
    [
        ("pybites", "super-secret-password"),
    ],
)
def test_local_vault(name: str, value: str, tmp_path: Path) -> None:
    vault = LocalVault(password="password", file=tmp_path / "secrets")
    vault.set(name=name, value=value)
    assert vault.get(name) == value
    vault.delete(name)
    assert vault.get(name) is None
