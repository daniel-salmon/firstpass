import base64
import os
from abc import ABC, abstractmethod
from functools import cached_property
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .secrets import Secret, Secrets, SecretsType

SALT_SIZE_BYTES = 16
PBKDF2_ITERATIONS = 600_000


class Vault(ABC):
    def __init__(self, password: str) -> None:
        self.password = password
        self.salt: bytes | None = None

    # TODO: Fernet uses AES 128 encryption. LastPass uses AES 256
    # May want to see if there is a setting we can toggle in the cryptography package
    # or if there is another package that would be suitable.
    @cached_property
    def cipher(self) -> Fernet:
        key = self._derive_key_from_password()
        return Fernet(key)

    def _derive_key_from_password(self) -> bytes:
        if self.salt is None:
            self.salt = os.urandom(SALT_SIZE_BYTES)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password.encode("utf-8")))

    def decrypt(self, blob: bytes) -> bytes:
        """Return the secrets encrypted in the blob object.

        To deserialize into a Secrets object, one must deserialize independently.
        This method is responsible only for decrypting the bytes themselves.

        Args:
            blob (bytes): The blob object encoding the salt and encrypted secrets.

        Returns:
            (bytes): The raw bytes of the secrets object.

        """
        # TODO: Update this using the minimum size of empty secrets.
        # E.g., an empty vault should have a blob size of salt + empty secrets
        assert len(blob) >= SALT_SIZE_BYTES
        salt, ciphertext = blob[:SALT_SIZE_BYTES], blob[SALT_SIZE_BYTES:]
        if self.salt != salt:
            # The salt recorded in the blob differs from the salt with which
            # our cipher was constructed (using salt + password to generate the key)
            # So we delete the cipher so that it can be recomputed using the
            # updated salt, instead of using the cached cipher.
            if self.salt is not None:
                del self.__dict__["cipher"]
            self.salt = salt
        return self.cipher.decrypt(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt(plaintext)
        return self.salt + ciphertext

    def get(self, secrets_type: SecretsType, name: str) -> Secret | None:
        secrets = self.fetch_secrets()
        subsecrets = getattr(secrets, secrets_type)
        return subsecrets.get(name) if subsecrets is not None else None

    def set(self, secrets_type: SecretsType, name: str, secret: Secret) -> None:
        secrets = self.fetch_secrets()
        subsecrets = getattr(secrets, secrets_type)
        if subsecrets is None:
            subsecrets = {}
            setattr(secrets, secrets_type, subsecrets)
        subsecrets[name] = secret
        self.write_secrets(secrets)

    def delete(self, secrets_type: SecretsType, name: str) -> None:
        secrets = self.fetch_secrets()
        subsecrets = getattr(secrets, secrets_type)
        if subsecrets is None or name not in subsecrets:
            return None
        del subsecrets[name]
        self.write_secrets(secrets)

    @abstractmethod
    def fetch_secrets(self) -> Secrets:
        pass

    @abstractmethod
    def write_secrets(self, secrets: Secrets) -> None:
        pass


class MemoryVault(Vault):
    def __init__(self, password) -> None:
        super().__init__(password)
        self.write_secrets(Secrets())

    def fetch_secrets(self) -> Secrets:
        return Secrets.deserialize(self.decrypt(self.blob))

    def write_secrets(self, secrets: Secrets) -> None:
        self.blob = self.encrypt(secrets.serialize())


class LocalVault(Vault):
    def __init__(self, password: str, file: Path) -> None:
        super().__init__(password)
        self.file = file
        if not self.file.exists() or self.file.stat().st_size == 0:
            self.setup_local_vault()

    def setup_local_vault(self, secrets: Secrets | None = None) -> None:
        if secrets is None:
            secrets = Secrets()
        with open(self.file, "wb") as f:
            f.write(self.encrypt(secrets.serialize()))

    def fetch_secrets(self) -> Secrets:
        with open(self.file, "rb") as f:
            secrets = Secrets.deserialize(self.decrypt(f.read()))
        return secrets

    def write_secrets(self, secrets: Secrets) -> None:
        with open(self.file, "wb") as f:
            f.write(self.encrypt(secrets.serialize()))
