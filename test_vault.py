import pytest

from vault import MemoryVault, Vault


@pytest.fixture()
def vault():
    return MemoryVault(password="password")


@pytest.mark.parametrize(
    "plaintext", [b"plaintext", b"what a string", b'{"pickles": "rule"}']
)
def test_encrypt_decrypt(plaintext: bytes, vault: Vault):
    assert vault.decrypt(vault.encrypt(plaintext)) == plaintext


@pytest.mark.parametrize(
    "name, value",
    [
        ("login1", "password1"),
        ("login2", "password2!xjbopajpoiabpoijweg"),
        ("ajapdfipjwe", "pebpjqefvp92!$T$!))"),
    ],
)
def test_set_get_delete(name: str, value: str, vault: Vault):
    vault.set(name, value)
    assert vault.get(name) == value
    vault.delete(name)
    assert vault.get(name) is None
