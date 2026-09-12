# -*- coding: utf-8 -*-
from abc import ABC, abstractmethod
from typing import List, Optional, Callable, TypeVar, Any
from .models import SecretStorageMetadata, StorageOptions

T = TypeVar('T')


class SecretStorageProvider(ABC):
    """
    Abstract base class for hardware-compatible secret storage providers.
    """

    @property
    @abstractmethod
    def provider_type(self) -> str:
        """Unique identifier of this provider implementation."""
        pass

    @property
    def providerType(self) -> str:
        return self.provider_type

    @abstractmethod
    def is_hardware_backed(self) -> bool:
        """
        True only when this provider holds a non-exportable key inside platform-secure
        hardware (Android TEE/StrongBox, Secure Enclave, TPM) and learned that from the
        platform itself - never from a caller argument. Software envelope providers
        return False. The value is persisted as metadata.hardwareBacked.
        """
        pass

    def isHardwareBacked(self) -> bool:
        return self.is_hardware_backed()

    @abstractmethod
    def is_available(self) -> bool:
        """Whether this storage backend is available in the current runtime."""
        pass

    def isAvailable(self) -> bool:
        return self.is_available()

    @abstractmethod
    def store_secret(
        self,
        bundle_hash: str,
        secret: str,
        options: Optional[Any] = None
    ) -> None:
        """Store and encrypt a master secret for the given bundle hash."""
        pass

    def storeSecret(self, bundle_hash: str, secret: str, options: Optional[Any] = None) -> None:
        return self.store_secret(bundle_hash, secret, options)

    @abstractmethod
    def retrieve_secret(
        self,
        bundle_hash: str,
        options: Optional[Any] = None
    ) -> Optional[str]:
        """Retrieve and decrypt the master secret for the given bundle hash."""
        pass

    def retrieveSecret(self, bundle_hash: str, options: Optional[Any] = None) -> Optional[str]:
        return self.retrieve_secret(bundle_hash, options)

    @abstractmethod
    def delete_secret(self, bundle_hash: str) -> bool:
        """Delete a stored secret."""
        pass

    def deleteSecret(self, bundle_hash: str) -> bool:
        return self.delete_secret(bundle_hash)

    @abstractmethod
    def has_secret(self, bundle_hash: str) -> bool:
        """Check if a secret exists for the given bundle hash."""
        pass

    def hasSecret(self, bundle_hash: str) -> bool:
        return self.has_secret(bundle_hash)

    @abstractmethod
    def list_secrets(self) -> List[SecretStorageMetadata]:
        """List all stored secret metadata without exposing plaintext secrets."""
        pass

    def listSecrets(self) -> List[SecretStorageMetadata]:
        return self.list_secrets()

    @abstractmethod
    def with_secret(
        self,
        bundle_hash: str,
        fn: Callable[[str], T],
        options: Optional[Any] = None
    ) -> T:
        """
        Execute a callback with the unwrapped secret and ensure cleanup.
        """
        pass

    def withSecret(self, bundle_hash: str, fn: Callable[[str], T], options: Optional[Any] = None) -> T:
        return self.with_secret(bundle_hash, fn, options)

    @abstractmethod
    def recover_secret(
        self,
        bundle_hash: str,
        recovery_passphrase: str,
        options: Optional[StorageOptions] = None
    ) -> None:
        """
        Recover a master secret using its recovery envelope and re-enroll it.
        Never returns or leaks the plaintext secret.
        """
        pass

    def recoverSecret(
        self,
        bundle_hash: str,
        recovery_passphrase: str,
        options: Optional[StorageOptions] = None
    ) -> None:
        return self.recover_secret(bundle_hash, recovery_passphrase, options)
