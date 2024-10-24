import json
from abc import ABC, abstractmethod
from functools import cached_property
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class Vault(ABC):
    def __init__(self, password: str) -> None:
        self.password = password

    @cached_property
    def cipher(self) -> Fernet:
        key = self._derive_key_from_password()
        return Fernet(key)

    def _derive_key_from_password(self) -> bytes:
        return Fernet.generate_key()

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.cipher.decrypt(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.cipher.encrypt(plaintext)

    def get(self, name: str) -> str | None:
        return self.fetch_secrets().get(name)

    def set(self, name: str, value: str) -> None:
        secrets = self.fetch_secrets()
        secrets[name] = value
        self.write_secrets(secrets)

    def delete(self, name: str) -> None:
        secrets = self.fetch_secrets()
        if name not in secrets:
            return
        del secrets[name]
        self.write_secrets(secrets)

    @abstractmethod
    def fetch_secrets(self) -> dict:
        pass

    @abstractmethod
    def write_secrets(self, secrets: dict) -> None:
        pass


class LocalVault(Vault):
    def __init__(self, password: str, file: Path) -> None:
        super().__init__(password)
        self.file = file

    def setup_local_vault(self, secrets: dict = {}) -> None:
        with open(self.file, "wb") as f:
            secrets = self.encrypt(json.dumps(secrets).encode("utf-8"))
            f.write(secrets)

    def fetch_secrets(self) -> dict:
        with open(self.file, "rb") as f:
            ciphertext = f.read()
            if ciphertext == b"":
                # If the ciphertext is empty, then this is the first
                # time reading from / writing to the vault and the vault will
                # be unencrypted, so we can't call decrypt on it
                secrets = {}
                self.setup_local_vault(secrets)
            else:
                secrets = self.decrypt(ciphertext)
                secrets = json.loads(secrets.decode("utf-8"))
        return secrets

    def write_secrets(self, secrets: dict) -> None:
        with open(self.file, "wb") as f:
            f.write(self.encrypt(json.dumps(secrets).encode("utf-8")))
