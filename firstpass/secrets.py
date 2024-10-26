from typing import Self

from pydantic import BaseModel
from pydantic_core import from_json


class Password(BaseModel):
    username: str
    password: str
    url: str | None = None
    notes: str | None = None


class Secrets(BaseModel):
    passwords: dict[str, Password] | None = None

    def serialize(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def deserialize(cls, secrets: bytes) -> Self:
        return cls(**from_json(secrets))
