import base64
import os
from abc import ABC, abstractmethod
from functools import cached_property
from pathlib import Path

import firstpass_client
from firstpass_client.models import Blob
from firstpass_client.rest import ApiException
from cryptography.fernet import Fernet, InvalidToken
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
        assert len(blob) >= SALT_SIZE_BYTES
        salt, ciphertext = blob[:SALT_SIZE_BYTES], blob[SALT_SIZE_BYTES:]
        if self.salt is None:
            self.salt = salt
        return self.cipher.decrypt(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt(plaintext)
        return self.salt + ciphertext

    def can_open(self) -> bool:
        try:
            _ = self.fetch_secrets()
        except InvalidToken:
            return False
        return True

    def list_names(self, secrets_type: SecretsType) -> set[str]:
        secrets = self.fetch_secrets()
        subsecrets = getattr(secrets, secrets_type)
        if subsecrets is None:
            return set()
        return set(subsecrets.keys())

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
            return
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


class CloudVault(Vault):
    def __init__(self, username: str, password: str, host: str) -> None:
        super().__init__(password)
        self.username = username
        self.host = host
        self.configuration = firstpass_client.Configuration(host=host)
        self.configuration.access_token = self._get_token()
        self.blob_id = self._get_blob_id()

    def _get_token(self) -> str:
        with firstpass_client.ApiClient(self.configuration) as api_client:
            api_instance = firstpass_client.DefaultApi(api_client)
            # TODO: We should hash the password so that the password remains zero-knowledge
            try:
                token = api_instance.token_token_post(
                    username=self.username, password=self.password
                )
            except firstpass_client.exceptions.UnauthorizedException:
                # TODO: Make custom exceptions for the vault?
                # Either the user entered the wrong password or the user doesn't exist
                # and needs created
                raise
            except ApiException:
                # TODO: Make custom exceptions for the vault?
                raise
        return token.access_token

    def _get_blob_id(self) -> str:
        with firstpass_client.ApiClient(self.configuration) as api_client:
            api_instance = firstpass_client.DefaultApi(api_client)
            try:
                user_get = api_instance.get_user_user_get()
            except ApiException:
                # TODO: Make custom exceptions for the vault?
                raise
        return user_get.blob_id

    def fetch_secrets(self) -> Secrets:
        with firstpass_client.ApiClient(self.configuration) as api_client:
            api_instance = firstpass_client.DefaultApi(api_client)
            try:
                blob = api_instance.get_blob_blob_blob_id_get(self.blob_id)
            except ApiException:
                # TODO: Make custom exceptions for the vault?
                raise
        blob_bytes = base64.b64decode(blob.blob)
        return Secrets.deserialize(self.decrypt(blob_bytes))

    def write_secrets(self, secrets: Secrets) -> None:
        with firstpass_client.ApiClient(self.configuration) as api_client:
            api_instance = firstpass_client.DefaultApi(api_client)
            try:
                blob_str = base64.b64encode(self.encrypt(secrets.serialize())).decode(
                    "utf-8"
                )
                blob = Blob(blob_id=self.blob_id, blob=blob_str)
                _ = api_instance.put_blob_blob_blob_id_put(
                    blob_id=self.blob_id, blob=blob
                )
            except ApiException:
                # TODO: Make custom exceptions for the vault?
                raise
