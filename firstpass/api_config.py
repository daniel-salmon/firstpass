from pathlib import Path
from typing import Any

from pydantic import ValidationError

from firstpass.lib.config import Config


def init(config_path: Path) -> None:
    config = Config()
    config.to_yaml(config_path)


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
        return
    except ValidationError:
        print(
            f"Provided value does not match schema. {key} requires type compatible with {Config.model_fields[key].annotation}"
        )
        return
    updated_config.to_yaml(config_path)


def reset(config_path: Path) -> None:
    try:
        config_path.unlink()
    except FileNotFoundError:
        print(f"Nothing to reset, no config file found at {config_path}")
        return
    init(config_path)
    print("Config reset to default settings")
