import pytest

from vault import LocalVault, Vault


@pytest.fixture()
def vault(tmp_path_factory: pytest.TempPathFactory):
    path = tmp_path_factory.mktemp(".firstpass")
    file = path / "vault"
    file.touch()
    vault = LocalVault(password="password", file=file)
    vault.setup_local_vault()
    return vault


@pytest.mark.parametrize(
    "plaintext",
    [b"plaintext", b"what a string", b'{"pickles": "rule"}']
)
def test_encrypt_decrypt(plaintext: bytes, vault: Vault):
    assert plaintext == vault.decrypt(vault.encrypt(plaintext))


@pytest.mark.parametrize(
    "name, value",
    [
        ("login1", "password1"),
        ("login2", "password2!xjbopajpoiabpoijweg"),
        ("ajapdfipjwe", "pebpjqefvp92!$T$!))"),
    ]
)
def test_set_get_delete(name: str, value: str, vault: Vault):
    vault.set(name, value)
    assert vault.get(name) == value
    vault.delete(name)
    assert vault.get(name) is None
