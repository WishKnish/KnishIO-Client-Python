# -*- coding: utf-8 -*-
from typing import Optional, Dict, Any
from .SecretStorageProvider import SecretStorageProvider
from .MemorySecretStorageProvider import MemorySecretStorageProvider
from .AesGcmSecretStorageProvider import AesGcmSecretStorageProvider


def create_default_secret_storage(options: Optional[Dict[str, Any]] = None) -> SecretStorageProvider:
    """
    Factory function to create a secret storage provider.
    """
    opts = options or {}
    storage_type = opts.get("type", "aes-gcm")
    if storage_type == "memory":
        return MemorySecretStorageProvider()

    return AesGcmSecretStorageProvider(
        backend=opts.get("backend"),
        default_passphrase=opts.get("defaultPassphrase", opts.get("default_passphrase"))
    )
