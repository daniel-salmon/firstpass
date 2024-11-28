from pathlib import Path
from typing import Generator

import firstpass_client
import pytest
from pydantic import SecretStr

from firstpass.utils import Config, LocalVault, Password, SecretsType, Vault

from . import CloudTest, ConfigTest

HOST = "http://localhost:8000"


@pytest.fixture(scope="function")
def default_local_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config = Config(local=True)
    config.to_yaml(config_path)
    config_test = ConfigTest(
        config=config, config_path=config_path, password="password"
    )
    return config_test


@pytest.fixture(scope="function")
def local_vault_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    vault_file = tmp_path / "vault"
    config = Config(local=True, vault_file=vault_file)
    config.to_yaml(config_path)
    config_test = ConfigTest(
        config=config, config_path=config_path, password="password"
    )
    return config_test


@pytest.fixture(scope="function")
def existing_empty_local_vault_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    vault_file = tmp_path / "vault"
    password = "password"
    LocalVault(password=password, file=vault_file)
    config = Config(local=True, vault_file=vault_file)
    config.to_yaml(config_path)
    config_test = ConfigTest(config=config, config_path=config_path, password=password)
    return config_test


@pytest.fixture(scope="function")
def existing_non_empty_local_vault_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    vault_file = tmp_path / "vault"
    password = "password"
    vault = LocalVault(password=password, file=vault_file)
    vault.set(
        secrets_type=SecretsType.passwords,
        name="pizza",
        secret=Password(
            label="Pizza",
            notes="is great",
            username="pepperoni",
            password=SecretStr("cheese"),
        ),
    )
    vault.set(
        secrets_type=SecretsType.passwords,
        name="pickles",
        secret=Password(
            label="Pickles",
            notes="are gross on pizza",
            username="cucumber",
            password=SecretStr("dill"),
        ),
    )
    vault.set(
        secrets_type=SecretsType.passwords,
        name="tickles",
        secret=Password(
            label="Tickles",
            notes="would be weird with pickles",
            username="fickles",
            password=SecretStr("onmytickles"),
        ),
    )
    config = Config(local=True, vault_file=vault_file)
    config.to_yaml(config_path)
    config_test = ConfigTest(config=config, config_path=config_path, password=password)
    return config_test


@pytest.fixture(scope="function")
def nonexistent_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config_test = ConfigTest(config=None, config_path=config_path, password="password")
    return config_test


@pytest.fixture(scope="function")
def exists_but_empty_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    config_path.touch()
    config_test = ConfigTest(config=None, config_path=config_path, password="password")
    return config_test


@pytest.fixture(scope="function")
def invalid_schema_config_test(tmp_path: Path) -> ConfigTest:
    config_path = tmp_path / "config.yaml"
    with open(config_path, "w", encoding="utf-8") as f:
        f.write("not a valid config")
    config_test = ConfigTest(config=None, config_path=config_path, password="password")
    return config_test


@pytest.fixture(scope="function")
def default_cloud_test_user_does_not_exist(
    tmp_path: Path,
) -> Generator[CloudTest, None, None]:
    password = "password"
    config_path = tmp_path / "config.yaml"
    config = Config(local=False, cloud_host=HOST)
    config.to_yaml(config_path)

    # Ensure the user doesn't exist in the backend
    configuration = firstpass_client.Configuration(host=config.cloud_host)
    with firstpass_client.ApiClient(configuration) as api_client:
        api_instance = firstpass_client.DefaultApi(api_client)
        try:
            token = api_instance.token_token_post(
                username=config.username, password=Vault.hash_password(password)
            )
            configuration.access_token = token.access_token
            api_instance.delete_user_user_delete()
        except firstpass_client.ApiException as e:
            if e.status != 401:
                raise
        yield CloudTest(config=config, config_path=config_path, password=password)
        try:
            token = api_instance.token_token_post(
                username=config.username, password=Vault.hash_password(password)
            )
            configuration.access_token = token.access_token
            api_instance.delete_user_user_delete()
        except firstpass_client.ApiException as e:
            if e.status != 401:
                raise


@pytest.fixture(scope="function")
def default_cloud_test_user_exists(tmp_path: Path) -> Generator[CloudTest, None, None]:
    password = "password"
    config_path = tmp_path / "config.yaml"
    config = Config(local=False, cloud_host=HOST)
    config.to_yaml(config_path)

    configuration = firstpass_client.Configuration(host=config.cloud_host)
    user_create = firstpass_client.UserCreate(
        username=config.username, password=Vault.hash_password(password)
    )
    with firstpass_client.ApiClient(configuration) as api_client:
        api_instance = firstpass_client.DefaultApi(api_client)
        token = api_instance.post_user_user_post(user_create)
        configuration.access_token = token.access_token
        yield CloudTest(config=config, config_path=config_path, password=password)
        api_instance.delete_user_user_delete()
