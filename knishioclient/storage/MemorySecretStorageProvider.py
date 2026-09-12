# -*- coding: utf-8 -*-
from typing import List, Optional, Callable, TypeVar, Any, Dict
import time
from .SecretStorageProvider import SecretStorageProvider
from .StorageBackend import StorageBackend, MemoryStorageBackend
from .models import SecretStorageMetadata, EncryptedSecretPayload, StorageOptions, RECOVERY_KEY_PREFIX
from .AesGcmSecretStorageProvider import seal_envelope, open_envelope
from ..exception.SecretStorageException import SecretStorageException
from ..libraries.crypto import with_secure_string

T = TypeVar('T')


class MemorySecretStorageProvider(SecretStorageProvider):
    """
    In-memory secret storage provider.
    Used for testing, headless runners, and backward-compatible fallback.
    """

    def __init__(self, backend: Optional[StorageBackend] = None) -> None:
        self._secrets: Dict[str, Dict[str, Any]] = {}
        self._recovery_secrets: Dict[str, str] = {}
        self.backend: StorageBackend = backend if backend is not None else MemoryStorageBackend()

    @property
    def provider_type(self) -> str:
        return "memory"

    def is_hardware_backed(self) -> bool:
        return False

    def is_available(self) -> bool:
        return True

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
        self._secrets[bundle_hash] = {
            "secret": secret,
            "metadata": metadata
        }

        if recovery_passphrase:
            recovery_metadata = SecretStorageMetadata(
                bundle_hash=bundle_hash,
                label=label,
                created_at=int(time.time() * 1000),
                hardware_backed=False,
                provider_type="aes-gcm"
            )
            recovery_payload = seal_envelope(secret, recovery_passphrase, recovery_metadata)
            recovery_json = recovery_payload.to_json()
            self._recovery_secrets[bundle_hash] = recovery_json
            self.backend.set_item(f"{RECOVERY_KEY_PREFIX}{bundle_hash}", recovery_json)

    def retrieve_secret(
        self,
        bundle_hash: str,
        options: Optional[Any] = None
    ) -> Optional[str]:
        _ = options
        entry = self._secrets.get(bundle_hash)
        return entry["secret"] if entry else None

    def delete_secret(self, bundle_hash: str) -> bool:
        self.backend.remove_item(f"{RECOVERY_KEY_PREFIX}{bundle_hash}")
        self._recovery_secrets.pop(bundle_hash, None)
        if bundle_hash in self._secrets:
            del self._secrets[bundle_hash]
            return True
        return False

    def has_secret(self, bundle_hash: str) -> bool:
        return bundle_hash in self._secrets
    def list_secrets(self) -> List[SecretStorageMetadata]:
        return [entry["metadata"] for entry in self._secrets.values()]

    def with_secret(
        self,
        bundle_hash: str,
        fn: Callable[[str], T],
        options: Optional[Any] = None
    ) -> T:
        _ = options
        entry = self._secrets.get(bundle_hash)
        if not entry:
            raise SecretStorageException.not_found(bundle_hash)
        return with_secure_string(entry["secret"], fn)

    def clear(self) -> None:
        self._secrets.clear()
        self._recovery_secrets.clear()
        for k in list(self.backend.keys()):
            self.backend.remove_item(k)

    def recover_secret(
        self,
        bundle_hash: str,
        recovery_passphrase: str,
        options: Optional[Any] = None
    ) -> None:
        """
        Recover a master secret using its recovery envelope and restore it.
        Never returns or leaks the plaintext secret.
        """
        if not bundle_hash:
            raise SecretStorageException("Bundle hash cannot be empty")
        if not recovery_passphrase:
            raise SecretStorageException("Recovery passphrase cannot be empty")

        raw = self.backend.get_item(f"{RECOVERY_KEY_PREFIX}{bundle_hash}") or self._recovery_secrets.get(bundle_hash)
        if raw is None:
            raise SecretStorageException.not_found(bundle_hash)

        try:
            payload = EncryptedSecretPayload.from_json(raw)
        except Exception as e:
            raise SecretStorageException.decryption_failed(f"Corrupted recovery payload format: {e}")

        plaintext = open_envelope(payload, recovery_passphrase)

        label = None
        allow_unrecoverable = False
        if options is not None:
            if isinstance(options, dict):
                label = options.get("label")
                allow_unrecoverable = bool(options.get("allow_unrecoverable") or options.get("allowUnrecoverable", False))
            elif hasattr(options, "label"):
                label = options.label
                allow_unrecoverable = getattr(options, "allow_unrecoverable", False)

        store_opts = StorageOptions(
            label=label,
            recovery_passphrase=recovery_passphrase,
            allow_unrecoverable=allow_unrecoverable,
        )

        try:
            self.store_secret(bundle_hash, plaintext, store_opts)
        finally:
            del plaintext

    recoverSecret = recover_secret
