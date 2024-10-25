import base64
import json
from abc import ABC, abstractmethod
from functools import cached_property
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000


class Vault(ABC):
    def __init__(self, password: str) -> None:
        self.password = password

    # TODO: Fernet uses AES 128 encryption. LastPass uses AES 256
    # May want to see if there is a setting we can toggle in the cryptography package
    # or if there is another package that would be suitable.
    @cached_property
    def cipher(self) -> Fernet:
        key = self._derive_key_from_password()
        return Fernet(key)

    def _derive_key_from_password(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"pinch of salt" * 2,
            iterations=PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password.encode("utf-8")))

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


class MemoryVault(Vault):
    def __init__(self, password) -> None:
        super().__init__(password)
        self.write_secrets({})

    def fetch_secrets(self) -> dict:
        return json.loads(self.decrypt(self.ciphertext).decode("utf-8"))

    def write_secrets(self, secrets: dict) -> None:
        self.ciphertext = self.encrypt(json.dumps(secrets).encode("utf-8"))


class LocalVault(Vault):
    def __init__(self, password: str, file: Path) -> None:
        super().__init__(password)
        self.file = file

    def setup_local_vault(self, secrets: dict | None = None) -> None:
        if secrets is None:
            secrets = {}
        with open(self.file, "wb") as f:
            encrypted_secrets = self.encrypt(json.dumps(secrets).encode("utf-8"))
            f.write(encrypted_secrets)

    def fetch_secrets(self) -> dict:
        secrets: dict = {}
        with open(self.file, "rb") as f:
            ciphertext = f.read()
            if not ciphertext:
                # If the ciphertext is empty, then this is the first
                # time reading from / writing to the vault and the vault will
                # be unencrypted, so we can't call decrypt on it
                self.setup_local_vault(secrets)
            else:
                raw_secrets = self.decrypt(ciphertext)
                secrets = json.loads(raw_secrets.decode("utf-8"))
        return secrets

    def write_secrets(self, secrets: dict) -> None:
        with open(self.file, "wb") as f:
            f.write(self.encrypt(json.dumps(secrets).encode("utf-8")))
