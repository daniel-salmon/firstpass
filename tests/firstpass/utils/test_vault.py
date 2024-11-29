import base64
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest
from firstpass_client import ApiException, Blob, Token, UserCreate, UserGet
from firstpass_client.exceptions import UnauthorizedException
from pydantic import SecretStr

from firstpass.utils import (
    CloudVault,
    LocalVault,
    MemoryVault,
    Password,
    Secret,
    Secrets,
    SecretsType,
    Vault,
    VaultInvalidUsernameOrPasswordError,
    VaultUnavailableError,
    VaultUsernameAlreadyExistsError,
)


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
            label="Entry",
            notes="notes",
            username="pickles",
            password=SecretStr("strongpassword"),
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
                    secret=Password(username="fish", password=SecretStr("password")),
                ),
            ]
        ),
        (
            [
                SecretGroup(
                    secrets_type=SecretsType.passwords,
                    name="login1",
                    secret=Password(username="fish", password=SecretStr("password")),
                ),
                SecretGroup(
                    secrets_type=SecretsType.passwords,
                    name="login2",
                    secret=Password(username="fish", password=SecretStr("password")),
                ),
                SecretGroup(
                    secrets_type=SecretsType.passwords,
                    name="login3",
                    secret=Password(username="fish", password=SecretStr("password")),
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
            SecretsType.passwords,
            "login1",
            Password(username="fish", password=SecretStr("password")),
        ),
        (
            SecretsType.passwords,
            "login2",
            Password(
                username="jumbalaya",
                password=SecretStr("password2!xjbopajpoiabpoijweg"),
            ),
        ),
        (
            SecretsType.passwords,
            "ajapdfipjwe",
            Password(username="pete", password=SecretStr("pebpjqefvp92!$T$!))")),
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
    "password, want",
    [
        (
            "password",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        ),
        (
            "notherpassword",
            "ac1a3146485f6ecec0bdec2514140c8763a9beffb2a14d47a931e9962c7d464c",
        ),
        (
            "pickled pizza piper",
            "18e33af62a6edf76fca092a0e7939d2fa9938d3d4008a6ab653941c48522174e",
        ),
    ],
)
def test_hash_password(password: str, want: str) -> None:
    assert Vault.hash_password(password) == want


@pytest.mark.parametrize(
    "secrets_type, name, secret",
    [
        (
            SecretsType.passwords,
            "pybites",
            Password(username="pybites", password=SecretStr("super-secret-password")),
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


def test_local_vault_remove(tmp_path: Path) -> None:
    vault_file = tmp_path / "vault"
    vault = LocalVault(password="password", file=vault_file)
    assert vault_file.exists()
    assert vault_file.stat().st_size > 0
    assert vault.can_open()
    vault.remove()
    assert not vault_file.exists()


@pytest.mark.parametrize(
    "username, password, host, token, user_get, specify_access_token_in_init",
    [
        (
            "bob",
            "password",
            "https://firstpass.com",
            Token(access_token="fake token", token_type="bearer"),
            UserGet(username="bob", blob_id="e2f2f1b7-83e9-4677-9438-8123445e615a"),
            False,
        ),
        (
            "bob",
            "password",
            "https://firstpass.com",
            Token(access_token="fake token", token_type="bearer"),
            UserGet(username="bob", blob_id="e2f2f1b7-83e9-4677-9438-8123445e615a"),
            True,
        ),
    ],
)
def test_cloud_vault_init(
    username: str,
    password: str,
    host: str,
    token: Token,
    user_get: UserGet,
    specify_access_token_in_init: bool,
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.token_token_post.return_value = (
            token if not specify_access_token_in_init else None
        )
        mock_api_instance.get_user_user_get.return_value = user_get
        if specify_access_token_in_init:
            cloud_vault = CloudVault(username, password, host, token.access_token)
        else:
            cloud_vault = CloudVault(username, password, host, None)
        assert cloud_vault.username == username
        assert cloud_vault.host == host
        assert cloud_vault.configuration.access_token == token.access_token
        assert cloud_vault.blob_id == user_get.blob_id
        if not specify_access_token_in_init:
            mock_api_instance.token_token_post.assert_called_with(
                username=username, password=Vault.hash_password(password)
            )
        mock_api_instance.get_user_user_get.assert_called()


@pytest.mark.parametrize(
    "username, password, host, token, user_get",
    [
        (
            "bob",
            "password",
            "https://firstpass.com",
            Token(access_token="fake token", token_type="bearer"),
            UserGet(username="bob", blob_id="e2f2f1b7-83e9-4677-9438-8123445e615a"),
        )
    ],
)
def test_cloud_vault_init_username_or_password_incorrect(
    username: str, password: str, host: str, token: Token, user_get: UserGet
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.token_token_post.side_effect = UnauthorizedException
        with pytest.raises(VaultInvalidUsernameOrPasswordError):
            _ = CloudVault(username, password, host, None)


@pytest.mark.parametrize(
    "username, password, host, token, user_get",
    [
        (
            "bob",
            "password",
            "https://firstpass.com",
            Token(access_token="fake token", token_type="bearer"),
            UserGet(username="bob", blob_id="e2f2f1b7-83e9-4677-9438-8123445e615a"),
        )
    ],
)
def test_cloud_vault_init_generic_error(
    username: str, password: str, host: str, token: Token, user_get: UserGet
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.token_token_post.side_effect = ApiException
        with pytest.raises(VaultUnavailableError):
            _ = CloudVault(username, password, host, None)


@pytest.mark.parametrize(
    "username, password, host, token",
    [
        ("bob", "password", "http://example.com", Token(access_token="access token")),
        (
            "tuna",
            "randompass",
            "http://example.com",
            Token(access_token="access token"),
        ),
    ],
)
def test_cloud_vault_create_new_user(
    username: str, password: str, host: str, token: Token
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.post_user_user_post.return_value = token
        got_token = CloudVault.create_new_user(
            username=username, password=password, host=host
        )
        assert got_token == token
        mock_api_instance.post_user_user_post.assert_called


@pytest.mark.parametrize(
    "username, password, host",
    [
        ("bob", "password", "http://example.com"),
    ],
)
def test_cloud_vault_create_new_user_username_already_exists_error(
    username: str, password: str, host: str
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.post_user_user_post.side_effect = ApiException(status=409)
        with pytest.raises(VaultUsernameAlreadyExistsError):
            _ = CloudVault.create_new_user(
                username=username, password=password, host=host
            )


@pytest.mark.parametrize(
    "username, password, host",
    [
        ("bob", "password", "http://example.com"),
    ],
)
def test_cloud_vault_create_new_user_generic_error(
    username: str, password: str, host: str
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.post_user_user_post.side_effect = ApiException
        with pytest.raises(VaultUnavailableError):
            _ = CloudVault.create_new_user(
                username=username, password=password, host=host
            )


@pytest.mark.parametrize(
    "username, password, host, token, user_get, secrets",
    [
        (
            "bob",
            "password",
            "https://firstpass.com",
            Token(access_token="fake token", token_type="bearer"),
            UserGet(username="bob", blob_id="e2f2f1b7-83e9-4677-9438-8123445e615a"),
            Secrets(),
        )
    ],
)
def test_cloud_vault_fetch_secrets(
    username: str,
    password: str,
    host: str,
    token: Token,
    user_get: UserGet,
    secrets: Secrets,
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.token_token_post.return_value = token
        mock_api_instance.get_user_user_get.return_value = user_get
        cloud_vault = CloudVault(username, password, host, None)
        want_blob_blob = base64.b64encode(
            cloud_vault.encrypt(secrets.serialize())
        ).decode("utf-8")
        want_blob = Blob(blob_id=user_get.blob_id, blob=want_blob_blob)
        mock_api_instance.get_blob_blob_blob_id_get.return_value = want_blob
        assert cloud_vault.fetch_secrets() == secrets
        mock_api_instance.get_blob_blob_blob_id_get.assert_called_with(
            blob_id=want_blob.blob_id
        )


@pytest.mark.parametrize(
    "username, password, host, token, user_get",
    [
        (
            "bob",
            "password",
            "https://firstpass.com",
            Token(access_token="fake token", token_type="bearer"),
            UserGet(username="bob", blob_id="e2f2f1b7-83e9-4677-9438-8123445e615a"),
        )
    ],
)
def test_cloud_vault_fetch_secrets_generic_error(
    username: str,
    password: str,
    host: str,
    token: Token,
    user_get: UserGet,
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.token_token_post.return_value = token
        mock_api_instance.get_user_user_get.return_value = user_get
        cloud_vault = CloudVault(username, password, host, None)
        mock_api_instance.get_blob_blob_blob_id_get.side_effect = ApiException
        with pytest.raises(VaultUnavailableError):
            _ = cloud_vault.fetch_secrets()


@pytest.mark.parametrize(
    "username, password, host, token, user_get, secrets",
    [
        (
            "bob",
            "password",
            "https://firstpass.com",
            Token(access_token="fake token", token_type="bearer"),
            UserGet(username="bob", blob_id="e2f2f1b7-83e9-4677-9438-8123445e615a"),
            Secrets(),
        )
    ],
)
def test_cloud_vault_write_secrets(
    username: str,
    password: str,
    host: str,
    token: Token,
    user_get: UserGet,
    secrets: Secrets,
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.token_token_post.return_value = token
        mock_api_instance.get_user_user_get.return_value = user_get
        cloud_vault = CloudVault(username, password, host, None)
        cloud_vault.write_secrets(secrets)
        mock_api_instance.put_blob_blob_blob_id_put.assert_called()


@pytest.mark.parametrize(
    "username, password, host, token, user_get, secrets",
    [
        (
            "bob",
            "password",
            "https://firstpass.com",
            Token(access_token="fake token", token_type="bearer"),
            UserGet(username="bob", blob_id="e2f2f1b7-83e9-4677-9438-8123445e615a"),
            Secrets(),
        )
    ],
)
def test_cloud_vault_write_secrets_generic_error(
    username: str,
    password: str,
    host: str,
    token: Token,
    user_get: UserGet,
    secrets: Secrets,
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.token_token_post.return_value = token
        mock_api_instance.get_user_user_get.return_value = user_get
        cloud_vault = CloudVault(username, password, host, None)
        mock_api_instance.put_blob_blob_blob_id_put.side_effect = ApiException
        with pytest.raises(VaultUnavailableError):
            cloud_vault.write_secrets(secrets)


@pytest.mark.parametrize(
    "username, password, host",
    [
        ("bob", "password", "http://example.com"),
    ],
)
def test_cloud_vault_remove(username: str, password: str, host: str) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        cloud_vault = CloudVault(
            username=username, password=password, host=host, access_token=None
        )
        cloud_vault.remove()
        mock_api_instance.delete_user_user_delete.assert_called()


@pytest.mark.parametrize(
    "username, password, host",
    [
        ("bob", "password", "http://example.com"),
    ],
)
def test_cloud_vault_remove_generic_error(
    username: str, password: str, host: str
) -> None:
    with patch("firstpass.utils.vault.firstpass_client", autospec=True) as mock_client:
        mock_api_instance = mock_client.DefaultApi.return_value
        mock_api_instance.delete_user_user_delete.side_effect = ApiException
        cloud_vault = CloudVault(
            username=username, password=password, host=host, access_token=None
        )
        with pytest.raises(VaultUnavailableError):
            cloud_vault.remove()
