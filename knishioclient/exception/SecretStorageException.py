# -*- coding: utf-8 -*-
from typing import Optional, Dict, Any
from .BaseError import BaseError


class SecretStorageException(BaseError):
    """
    Exception thrown when a secret storage or hardware envelope encryption operation fails.
    """

    def __init__(
        self,
        message: str = 'Secret storage operation failed.',
        code: int = 1,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        *args,
        **kwargs
    ) -> None:
        self.error_code: Optional[str] = error_code or kwargs.pop('error_code', None)
        self.details: Optional[Dict[str, Any]] = details or kwargs.pop('details', None)
        super(SecretStorageException, self).__init__(message, code, *args)

    @classmethod
    def not_found(cls, bundle_hash: str) -> "SecretStorageException":
        """
        Secret not found for the requested bundle hash.
        """
        return cls(
            f"Secret not found for bundle: {bundle_hash}",
            code=1,
            error_code="SECRET_NOT_FOUND",
            details={"bundle_hash": bundle_hash, "bundleHash": bundle_hash}
        )

    @classmethod
    def decryption_failed(cls, reason: Optional[str] = None) -> "SecretStorageException":
        """
        Decryption failed (wrong passphrase or corrupted payload).
        """
        return cls(
            f"Failed to decrypt master secret: {reason or 'Invalid passphrase or corrupted ciphertext'}",
            code=1,
            error_code="DECRYPTION_FAILED",
            details={"reason": reason}
        )

    @classmethod
    def unavailable(cls, provider: str, reason: Optional[str] = None) -> "SecretStorageException":
        """
        Provider is unavailable in current platform.
        """
        return cls(
            f"Secret storage provider '{provider}' is unavailable: {reason or 'Hardware or API not accessible'}",
            code=1,
            error_code="STORAGE_UNAVAILABLE",
            details={"provider": provider, "reason": reason}
        )

    # Cross-SDK camelCase aliases
    notFound = not_found
    decryptionFailed = decryption_failed
