from dataclasses import dataclass
from pathlib import Path

from firstpass.utils import Config


@dataclass
class ConfigTest:
    config: Config | None
    config_path: Path
    password: str
