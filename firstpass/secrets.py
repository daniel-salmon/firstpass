from enum import StrEnum
from typing import Self

from pydantic import BaseModel
from pydantic_core import from_json


class Secret(BaseModel):
    label: str | None = None
    notes: str | None = None


class Password(Secret):
    username: str
    password: str


class Secrets(BaseModel):
    passwords: dict[str, Password] | None = None

    def serialize(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def deserialize(cls, secrets: bytes) -> Self:
        return cls(**from_json(secrets))


SecretsType = StrEnum("SecretsType", list(Secrets.model_fields))  # type: ignore
