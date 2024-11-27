import pytest
from pathlib import Path

from pydantic import SecretStr

from . import ConfigTest
from firstpass.utils import Config, LocalVault, SecretsType, Password


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
