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


SecretPart = StrEnum("SecretPart", ["all", "label", "notes", "username", "password"])


class Secrets(BaseModel):
    passwords: dict[str, Password] | None = None

    def serialize(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def deserialize(cls, secrets: bytes) -> Self:
        return cls(**from_json(secrets))


SecretsType = StrEnum("SecretsType", ["passwords"])


# TODO: Update type hint of the return value to be a Pydantic BaseModel
# type (but it is not an instance of BaseModel)
def get_name_from_secrets_type(secrets_type: SecretsType) -> type:
    match secrets_type:
        case SecretsType.passwords:
            return Password
        case _:
            return Secret
