# -*- coding: utf-8 -*-
from typing import Optional, Dict, Any, Union
import json
import time


class SecretStorageMetadata:
    """
    Metadata associated with an encrypted secret in storage.
    Must emit camelCase keys in dict/json representation:
    Required: bundleHash, createdAt, hardwareBacked, providerType.
    Optional: label (omitted when unset/None, never null).
    Forbidden: snake_case (bundle_hash, created_at, hardware_backed, provider_type).
    """

    def __init__(
        self,
        bundle_hash: Optional[str] = None,
        label: Optional[str] = None,
        created_at: Optional[int] = None,
        hardware_backed: bool = False,
        provider_type: str = "aes-gcm",
        bundleHash: Optional[str] = None,
        createdAt: Optional[int] = None,
        hardwareBacked: Optional[bool] = None,
        providerType: Optional[str] = None,
    ) -> None:
        self.bundle_hash = bundleHash if bundleHash is not None else (bundle_hash or "")
        self.label = label
        if createdAt is not None:
            self.created_at = createdAt
        elif created_at is not None:
            self.created_at = created_at
        else:
            self.created_at = int(time.time() * 1000)
        self.hardware_backed = hardwareBacked if hardwareBacked is not None else hardware_backed
        self.provider_type = providerType if providerType is not None else provider_type

    @property
    def bundleHash(self) -> str:
        return self.bundle_hash

    @property
    def createdAt(self) -> int:
        return self.created_at

    @property
    def hardwareBacked(self) -> bool:
        return self.hardware_backed

    @property
    def providerType(self) -> str:
        return self.provider_type

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "bundleHash": self.bundle_hash,
            "createdAt": self.created_at,
            "hardwareBacked": self.hardware_backed,
            "providerType": self.provider_type,
        }
        if self.label is not None:
            result["label"] = self.label
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecretStorageMetadata":
        return cls(
            bundle_hash=data.get("bundleHash", data.get("bundle_hash")),
            label=data.get("label"),
            created_at=data.get("createdAt", data.get("created_at")),
            hardware_backed=data.get("hardwareBacked", data.get("hardware_backed", False)),
            provider_type=data.get("providerType", data.get("provider_type", "aes-gcm")),
        )


class EncryptedSecretPayload:
    """
    Versioned cross-SDK envelope encryption payload.
    """

    def __init__(
        self,
        ciphertext: str,
        iv: str,
        salt: str,
        metadata: Union[SecretStorageMetadata, Dict[str, Any]],
        version: int = 1,
        algorithm: str = "AES-GCM",
        iterations: int = 100000,
        tag: Optional[str] = None,
    ) -> None:
        self.version = version
        self.ciphertext = ciphertext
        self.iv = iv
        self.salt = salt
        self.algorithm = algorithm
        self.iterations = iterations
        self.tag = tag
        if isinstance(metadata, dict):
            self.metadata = SecretStorageMetadata.from_dict(metadata)
        else:
            self.metadata = metadata

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "version": self.version,
            "ciphertext": self.ciphertext,
            "iv": self.iv,
            "salt": self.salt,
            "algorithm": self.algorithm,
            "iterations": self.iterations,
            "metadata": self.metadata.to_dict() if hasattr(self.metadata, "to_dict") else self.metadata,
        }
        if self.tag is not None:
            result["tag"] = self.tag
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptedSecretPayload":
        return cls(
            version=data.get("version", 1),
            ciphertext=data["ciphertext"],
            iv=data["iv"],
            salt=data["salt"],
            algorithm=data.get("algorithm", "AES-GCM"),
            iterations=data.get("iterations", 100000),
            metadata=data["metadata"],
            tag=data.get("tag"),
        )

    @classmethod
    def from_json(cls, raw: str) -> "EncryptedSecretPayload":
        return cls.from_dict(json.loads(raw))


RECOVERY_KEY_PREFIX = "knishio:recovery:"
SECRET_KEY_PREFIX = "knishio:secret:"


class StorageOptions:
    """
    Storage options for operations like passphrase, recovery, and custom label.
    """

    def __init__(
        self,
        label: Optional[str] = None,
        passphrase: Optional[str] = None,
        recovery_passphrase: Optional[str] = None,
        allow_unrecoverable: bool = False,
        recoveryPassphrase: Optional[str] = None,
        allowUnrecoverable: Optional[bool] = None,
    ) -> None:
        self.label = label
        self.passphrase = passphrase
        self.recovery_passphrase = (
            recoveryPassphrase if recoveryPassphrase is not None else recovery_passphrase
        )
        self.allow_unrecoverable = (
            allowUnrecoverable if allowUnrecoverable is not None else allow_unrecoverable
        )

    @property
    def recoveryPassphrase(self) -> Optional[str]:
        return self.recovery_passphrase

    @recoveryPassphrase.setter
    def recoveryPassphrase(self, value: Optional[str]) -> None:
        self.recovery_passphrase = value

    @property
    def allowUnrecoverable(self) -> bool:
        return self.allow_unrecoverable

    @allowUnrecoverable.setter
    def allowUnrecoverable(self, value: bool) -> None:
        self.allow_unrecoverable = value
