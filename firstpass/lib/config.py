import json
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ValidationError

from firstpass.lib.exceptions import ConfigKeyDoesNotExistError, ConfigValidationError


class Config(BaseModel):
    cloud_host: str = "http://localhost:8000"
    local: bool = False
    username: str = "username"
    vault_file: Path = Path.home() / Path(".firstpass/vault")

    @classmethod
    def from_yaml(cls, path: Path) -> Self:
        with open(path, "r", encoding="utf-8") as f:
            c = yaml.safe_load(f)
        return cls(**c)

    def to_yaml(self, path: Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            # Use the Pydantic model's JSON serializer to ensure Python objects get
            # serialized correctly for YAML
            yaml.dump(json.loads(self.json()), f)

    def list_keys(self) -> set[str]:
        return set(self.model_dump().keys())


def update_config(config: Config, key: str, value: str) -> Config:
    if not hasattr(config, key):
        raise ConfigKeyDoesNotExistError
    config_dict = config.model_dump()
    config_dict[key] = value
    try:
        config = Config(**config_dict)
    except ValidationError:
        raise ConfigValidationError
    return config
