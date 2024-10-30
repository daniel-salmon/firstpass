from enum import StrEnum
from typing import Self

from pydantic import BaseModel
from pydantic_core import from_json


class Secret:
    pass


class Password(Secret, BaseModel):
    username: str
    password: str
    label: str | None = None
    notes: str | None = None


class SecretsType(StrEnum):
    passwords = "passwords"


class Secrets(BaseModel):
    passwords: dict[str, Password] | None = None

    def serialize(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def deserialize(cls, secrets: bytes) -> Self:
        return cls(**from_json(secrets))
