from pathlib import Path

import pytest

from firstpass.utils import (
    Config,
    ConfigKeyDoesNotExistError,
    ConfigValidationError,
    update_config,
)


@pytest.mark.parametrize(
    "config",
    [
        Config(),
        Config(cloud_host="https://firstpass.com", local=False, username="daniel"),
    ],
)
def test_read_write_config(config: Config, tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    config.to_yaml(path)
    assert Config.from_yaml(path) == config


@pytest.mark.parametrize(
    "config, key, value, want_config, exception",
    [
        (Config(), "local", "True", Config(local=True), None),
        (
            Config(),
            "cloud_host",
            "https://firstpass.com",
            Config(cloud_host="https://firstpass.com"),
            None,
        ),
        (Config(), "nonexistentkey", "value", None, ConfigKeyDoesNotExistError),
        (Config(), "local", "NotABool", None, ConfigValidationError),
    ],
)
def test_update_config(
    config: Config,
    key: str,
    value: str,
    want_config: Config | None,
    exception: Exception,
) -> None:
    if exception is not None:
        with pytest.raises(exception):
            _ = update_config(config, key, value)
        return
    got_config = update_config(config, key, value)
    assert got_config == want_config
