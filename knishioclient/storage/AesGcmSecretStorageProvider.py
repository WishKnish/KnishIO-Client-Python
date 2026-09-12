# -*- coding: utf-8 -*-
import base64
import hashlib
import os
import time
from typing import List, Optional, Callable, TypeVar, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .SecretStorageProvider import SecretStorageProvider
from .StorageBackend import StorageBackend, MemoryStorageBackend
from .models import (
    SecretStorageMetadata,
    EncryptedSecretPayload,
    StorageOptions,
    RECOVERY_KEY_PREFIX,
    SECRET_KEY_PREFIX,
)
from ..exception.SecretStorageException import SecretStorageException
from ..libraries.crypto import zeroize, with_secure_string

T = TypeVar('T')

KEY_PREFIX = SECRET_KEY_PREFIX
ENVELOPE_ALGORITHM = "AES-GCM"
DEFAULT_ITERATIONS = 100000
GCM_IV_LENGTH = 12
SALT_LENGTH = 16


def seal_envelope(
    secret: str,
    passphrase: str,
    metadata: SecretStorageMetadata,
    iterations: int = DEFAULT_ITERATIONS
) -> EncryptedSecretPayload:
    """
    Seal a secret string into an EncryptedSecretPayload envelope using AES-GCM
    and PBKDF2-HMAC-SHA256 key derivation.
    """
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(GCM_IV_LENGTH)

    passphrase_bytes = passphrase.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', passphrase_bytes, salt, iterations, 32)

    secret_bytes = bytearray(secret.encode('utf-8'))
    try:
        aesgcm = AESGCM(key)
        # AESGCM.encrypt in cryptography appends the 16-byte authentication tag to ciphertext
        ciphertext_bytes = aesgcm.encrypt(iv, bytes(secret_bytes), None)

        return EncryptedSecretPayload(
            version=1,
            ciphertext=base64.b64encode(ciphertext_bytes).decode('ascii'),
            iv=base64.b64encode(iv).decode('ascii'),
            salt=base64.b64encode(salt).decode('ascii'),
            algorithm=ENVELOPE_ALGORITHM,
            iterations=iterations,
            metadata=metadata
        )
    finally:
        zeroize(secret_bytes)


def open_envelope(
    payload: EncryptedSecretPayload,
    passphrase: str
) -> str:
    """
    Open an EncryptedSecretPayload envelope with a passphrase, returning the decrypted secret.
    """
    try:
        salt = base64.b64decode(payload.salt)
        iv = base64.b64decode(payload.iv)
        ciphertext = base64.b64decode(payload.ciphertext)
        if payload.tag:
            ciphertext += base64.b64decode(payload.tag)
    except Exception as e:
        raise SecretStorageException.decryption_failed(f"Corrupted base64 payload: {e}")

    iterations = payload.iterations or DEFAULT_ITERATIONS
    passphrase_bytes = passphrase.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', passphrase_bytes, salt, iterations, 32)

    try:
        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
    except Exception as e:
        raise SecretStorageException.decryption_failed(str(e) or "Authentication failed")

    return decrypted_bytes.decode('utf-8')


class AesGcmSecretStorageProvider(SecretStorageProvider):
    """
    Standard AES-GCM envelope encryption secret storage provider.
    Software provider: never hardware-backed.
    """

    def __init__(
        self,
        backend: Optional[StorageBackend] = None,
        default_passphrase: Optional[str] = None,
        defaultPassphrase: Optional[str] = None,
        **kwargs
    ) -> None:
        _ = kwargs
        self.backend = backend if backend is not None else MemoryStorageBackend()
        self.default_passphrase = defaultPassphrase if defaultPassphrase is not None else default_passphrase

    @property
    def provider_type(self) -> str:
        return "aes-gcm"

    def is_hardware_backed(self) -> bool:
        return False

    def is_available(self) -> bool:
        return True

    def _resolve_passphrase(self, options: Optional[Any]) -> str:
        passphrase = None
        if options is not None:
            if isinstance(options, dict):
                passphrase = options.get("passphrase")
            elif hasattr(options, "passphrase"):
                passphrase = options.passphrase
            elif isinstance(options, str):
                passphrase = options
        if passphrase is None:
            passphrase = self.default_passphrase
        if not passphrase:
            raise SecretStorageException("Passphrase required for envelope encryption")
        return passphrase

    def store_secret(
        self,
        bundle_hash: str,
        secret: str,
        options: Optional[Any] = None
    ) -> None:
        if not bundle_hash:
            raise SecretStorageException("Bundle hash cannot be empty")
        if not secret:
            raise SecretStorageException("Secret cannot be empty")

        passphrase = self._resolve_passphrase(options)

        label = None
        recovery_passphrase = None
        if options is not None:
            if isinstance(options, dict):
                label = options.get("label")
                recovery_passphrase = options.get("recovery_passphrase") or options.get("recoveryPassphrase")
            elif hasattr(options, "label"):
                label = options.label
                recovery_passphrase = getattr(options, "recovery_passphrase", None) or getattr(options, "recoveryPassphrase", None)

        metadata = SecretStorageMetadata(
            bundle_hash=bundle_hash,
            label=label,
            created_at=int(time.time() * 1000),
            hardware_backed=False,
            provider_type=self.provider_type
        )

        try:
            payload = seal_envelope(secret, passphrase, metadata)
            payload_json = payload.to_json()
            self.backend.set_item(f"{KEY_PREFIX}{bundle_hash}", payload_json)

            if recovery_passphrase:
                recovery_metadata = SecretStorageMetadata(
                    bundle_hash=bundle_hash,
                    label=label,
                    created_at=int(time.time() * 1000),
                    hardware_backed=False,
                    provider_type="aes-gcm"
                )
                recovery_payload = seal_envelope(secret, recovery_passphrase, recovery_metadata)
                self.backend.set_item(f"{RECOVERY_KEY_PREFIX}{bundle_hash}", recovery_payload.to_json())
        except SecretStorageException:
            raise
        except Exception as e:
            raise SecretStorageException(f"Encryption failed: {e}")

    def retrieve_secret(
        self,
        bundle_hash: str,
        options: Optional[Any] = None
    ) -> Optional[str]:
        raw = self.backend.get_item(f"{KEY_PREFIX}{bundle_hash}")
        if raw is None:
            return None

        try:
            payload = EncryptedSecretPayload.from_json(raw)
        except Exception as e:
            raise SecretStorageException.decryption_failed(f"Corrupted payload format: {e}")

        passphrase = self._resolve_passphrase(options)
        return open_envelope(payload, passphrase)

    def delete_secret(self, bundle_hash: str) -> bool:
        self.backend.remove_item(f"{RECOVERY_KEY_PREFIX}{bundle_hash}")
        return self.backend.remove_item(f"{KEY_PREFIX}{bundle_hash}")

    def has_secret(self, bundle_hash: str) -> bool:
        return self.backend.get_item(f"{KEY_PREFIX}{bundle_hash}") is not None

    def list_secrets(self) -> List[SecretStorageMetadata]:
        result = []
        for key in self.backend.keys():
            if key.startswith(KEY_PREFIX) and not key.startswith(RECOVERY_KEY_PREFIX):
                raw = self.backend.get_item(key)
                if raw:
                    try:
                        payload = EncryptedSecretPayload.from_json(raw)
                        result.append(payload.metadata)
                    except Exception:
                        pass
        return result

    def with_secret(
        self,
        bundle_hash: str,
        fn: Callable[[str], T],
        options: Optional[Any] = None
    ) -> T:
        secret = self.retrieve_secret(bundle_hash, options)
        if secret is None:
            raise SecretStorageException.not_found(bundle_hash)
        return with_secure_string(secret, fn)

    def recover_secret(
        self,
        bundle_hash: str,
        recovery_passphrase: str,
        options: Optional[Any] = None
    ) -> None:
        """
        Recover a master secret using its recovery envelope and re-enroll it.
        Never returns or leaks the plaintext secret.
        """
        if not bundle_hash:
            raise SecretStorageException("Bundle hash cannot be empty")
        if not recovery_passphrase:
            raise SecretStorageException("Recovery passphrase cannot be empty")

        raw = self.backend.get_item(f"{RECOVERY_KEY_PREFIX}{bundle_hash}")
        if raw is None:
            raise SecretStorageException.not_found(bundle_hash)

        try:
            payload = EncryptedSecretPayload.from_json(raw)
        except Exception as e:
            raise SecretStorageException.decryption_failed(f"Corrupted recovery payload format: {e}")

        plaintext = open_envelope(payload, recovery_passphrase)

        passphrase = None
        label = None
        allow_unrecoverable = False
        if options is not None:
            if isinstance(options, dict):
                passphrase = options.get("passphrase")
                label = options.get("label")
                allow_unrecoverable = bool(options.get("allow_unrecoverable") or options.get("allowUnrecoverable", False))
            elif hasattr(options, "passphrase"):
                passphrase = options.passphrase
                label = getattr(options, "label", None)
                allow_unrecoverable = getattr(options, "allow_unrecoverable", False)
            elif isinstance(options, str):
                passphrase = options

        store_passphrase = passphrase or self.default_passphrase or recovery_passphrase

        store_opts = StorageOptions(
            label=label,
            passphrase=store_passphrase,
            recovery_passphrase=recovery_passphrase,
            allow_unrecoverable=allow_unrecoverable,
        )

        try:
            self.store_secret(bundle_hash, plaintext, store_opts)
        finally:
            del plaintext

    recoverSecret = recover_secret
