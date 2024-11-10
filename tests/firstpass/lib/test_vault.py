from collections import defaultdict
from dataclasses import dataclass

import pytest
from pathlib import Path

from firstpass.lib.vault import LocalVault, MemoryVault, Vault
from firstpass.lib.secrets import Secret, Password, SecretsType


@dataclass
class SecretGroup:
    secrets_type: SecretsType
    name: str
    secret: Secret


@pytest.fixture()
def vault() -> Vault:
    return MemoryVault(password="password")


@pytest.mark.parametrize(
    "plaintext", [b"plaintext", b"what a string", b'{"pickles": "rule"}']
)
def test_encrypt_decrypt(plaintext: bytes, vault: Vault) -> None:
    assert vault.decrypt(vault.encrypt(plaintext)) == plaintext


def test_can_open() -> None:
    m1 = MemoryVault(password="password")
    m1.set(
        secrets_type=SecretsType.passwords,
        name="entry",
        secret=Password(
            label="Entry", notes="notes", username="pickles", password="strongpassword"
        ),
    )
    m2 = MemoryVault(password="differentpassword")
    m2.blob = m1.blob
    assert not m2.can_open()

    # Test that even with the same password we still can't decrypt since the salts are different
    m2.password = m1.password
    del m2.cipher
    assert not m2.can_open()

    # Now with equal passwords and salts we should be able to decrypt
    m2.salt = m1.salt
    del m2.cipher
    assert m2.can_open()


@pytest.mark.parametrize(
    "secret_groups",
    [
        ([]),
        (
            [
                SecretGroup(
                    secrets_type=SecretsType.passwords,
                    name="login1",
                    secret=Password(username="fish", password="password"),
                ),
            ]
        ),
        (
            [
                SecretGroup(
                    secrets_type=SecretsType.passwords,
                    name="login1",
                    secret=Password(username="fish", password="password"),
                ),
                SecretGroup(
                    secrets_type=SecretsType.passwords,
                    name="login2",
                    secret=Password(username="fish", password="password"),
                ),
                SecretGroup(
                    secrets_type=SecretsType.passwords,
                    name="login3",
                    secret=Password(username="fish", password="password"),
                ),
            ]
        ),
    ],
)
def test_list_names(secret_groups: list[SecretGroup], vault: Vault) -> None:
    expected_names = defaultdict(set)
    for secret_group in secret_groups:
        expected_names[secret_group.secrets_type].add(secret_group.name)
        vault.set(
            secrets_type=secret_group.secrets_type,
            name=secret_group.name,
            secret=secret_group.secret,
        )
    for secrets_type in SecretsType:
        assert vault.list_names(secrets_type) == expected_names[secrets_type]


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
