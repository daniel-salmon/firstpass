import pytest

import firstpass_client
from pydantic import BaseModel, SecretStr

from firstpass.lib import (
    CloudVault,
    Password,
    Secret,
    Secrets,
    SecretsType,
    Vault,
    VaultInvalidUsernameOrPasswordError,
)


HOST = "http://localhost:8000"


class User(BaseModel):
    username: str
    password: str
    host: str
    blob_id: str | None


def init_user(user: User) -> None:
    configuration = firstpass_client.Configuration(host=user.host)
    with firstpass_client.ApiClient(configuration) as api_client:
        api_instance = firstpass_client.DefaultApi(api_client)
        user_create = firstpass_client.UserCreate(
            username=user.username, password=Vault.hash_password(user.password)
        )
        try:
            token = api_instance.post_user_user_post(user_create)
        except firstpass_client.ApiException as api_exception:
            # User already exists
            if api_exception.status != 409:
                raise
            token = api_instance.token_token_post(
                username=user.username, password=Vault.hash_password(user.password)
            )
        configuration.access_token = token.access_token
        # Set up the user's vault if it doesn't already exist
        cloud_vault = CloudVault(
            username=user.username,
            password=user.password,
            host=user.host,
            access_token=None,
        )
        try:
            _ = cloud_vault.fetch_secrets()
        except TypeError:
            cloud_vault.write_secrets(Secrets())
        user_get = api_instance.get_user_user_get()
        user.blob_id = user_get.blob_id


@pytest.fixture(scope="module")
def user1() -> User:
    user = User(username="user1", password="password", host=HOST, blob_id=None)
    init_user(user)
    return user


@pytest.fixture(scope="module")
def user2() -> User:
    user = User(username="user2", password="gibberish", host=HOST, blob_id=None)
    init_user(user)
    return user


@pytest.mark.parametrize(
    "user_str, secrets_type, name, secret",
    [
        (
            "user1",
            SecretsType.passwords,
            "pybites",
            Password(username="user1", password=SecretStr("super-secret-password")),
        ),
        (
            "user2",
            SecretsType.passwords,
            "pizza",
            Password(username="user2", password=SecretStr("pickles")),
        ),
    ],
)
def test_cloud_vault(
    user_str: str,
    secrets_type: SecretsType,
    name: str,
    secret: Secret,
    request: pytest.FixtureRequest,
) -> None:
    user = request.getfixturevalue(user_str)
    vault = CloudVault(
        username=user.username,
        password=user.password,
        host=user.host,
        access_token=None,
    )
    vault.set(secrets_type, name, secret)
    assert vault.get(secrets_type, name) == secret
    vault.delete(secrets_type, name)
    assert vault.get(secrets_type, name) is None


@pytest.mark.parametrize(
    "user_str",
    ["user1", "user2"],
)
def test_cloud_vault_wrong_password(user_str: str, request: pytest.FixtureRequest):
    user = request.getfixturevalue(user_str)
    with pytest.raises(VaultInvalidUsernameOrPasswordError):
        _ = CloudVault(
            username=user.username,
            password=user.password + "extra",
            host=user.host,
            access_token=None,
        )


@pytest.mark.parametrize(
    "username",
    ["353897d1-e0d8-4fd6-a787-82f403d2cdf7", "92c733d5-f908-476b-8e25-9978cdb53595"],
)
def test_cloud_vault_invalid_username(username: str):
    with pytest.raises(VaultInvalidUsernameOrPasswordError):
        _ = CloudVault(
            username=username, password="password", host=HOST, access_token=None
        )
