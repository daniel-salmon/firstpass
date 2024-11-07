from pathlib import Path
from typing import Any

from pydantic import ValidationError

from firstpass.lib.config import Config


def list_keys(config: Config):
    print("\n".join(config.model_dump().keys()))


def get(config: Config, key: str) -> Any:
    try:
        value = getattr(config, key)
    except AttributeError:
        print(f"{key} is not a setting")
        return
    print(f"{key}={value}")


def _set(config: Config, key: str, value: str) -> Config:
    if not hasattr(config, key):
        raise AttributeError
    config_dict = config.model_dump()
    config_dict[key] = value
    config = Config(**config_dict)
    return config


def set(config: Config, key: str, value: str, config_path: Path) -> None:
    try:
        updated_config = _set(config, key, value)
    except AttributeError:
        print(f"{key} is not a setting")
    except ValidationError:
        pass
    updated_config.to_yaml(config_path)
