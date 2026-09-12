# -*- coding: utf-8 -*-
from abc import ABC, abstractmethod
from typing import List, Optional, Dict
from pathlib import Path
import json
import os
import threading
import uuid


class StorageBackend(ABC):
    """
    Pluggable key-value storage backend adapter interface.
    """

    @abstractmethod
    def get_item(self, key: str) -> Optional[str]:
        """Retrieve stored value for key, or None if not found."""
        pass

    @abstractmethod
    def set_item(self, key: str, value: str) -> None:
        """Store key-value pair."""
        pass

    @abstractmethod
    def remove_item(self, key: str) -> bool:
        """Remove item by key. Returns True if removed, False if not present."""
        pass

    @abstractmethod
    def keys(self) -> List[str]:
        """Return list of all keys in storage."""
        pass

    # CamelCase aliases for cross-SDK compatibility
    def getItem(self, key: str) -> Optional[str]:
        return self.get_item(key)

    def setItem(self, key: str, value: str) -> None:
        self.set_item(key, value)

    def removeItem(self, key: str) -> bool:
        return self.remove_item(key)


class MemoryStorageBackend(StorageBackend):
    """
    In-memory thread-safe key-value storage backend.
    """

    def __init__(self) -> None:
        self._store: Dict[str, str] = {}
        self._lock = threading.RLock()

    def get_item(self, key: str) -> Optional[str]:
        with self._lock:
            return self._store.get(key)

    def set_item(self, key: str, value: str) -> None:
        with self._lock:
            self._store[key] = str(value)

    def remove_item(self, key: str) -> bool:
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def keys(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


class FileStorageBackend(StorageBackend):
    """
    Atomic file-based key-value persistence backend storing key-value pairs
    as JSON with restrictive permissions (0o600 on Unix) and atomic replacement.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        if self.path.is_dir():
            self.path = self.path / "secrets.json"

        self._lock = threading.RLock()
        self._store: Dict[str, str] = {}

        parent = self.path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)

        if self.path.exists():
            try:
                content = self.path.read_text(encoding="utf-8")
                self._store = json.loads(content)
            except Exception as e:
                from ..exception.SecretStorageException import SecretStorageException
                raise SecretStorageException(f"Failed to read storage file at {self.path}: {e}")

    def _persist(self) -> None:
        """
        Atomically writes _store to disk via a temporary file with mode 0o600 and atomic rename.
        """
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)

        tmp_path = parent / f"{self.path.name}.tmp.{uuid.uuid4().hex}"
        try:
            # Open file descriptor with restrictive mode 0o600
            fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(self._store, f, indent=2)
                f.flush()
                try:
                    os.fsync(fd)
                except OSError:
                    pass
            # Atomic rename / replace
            os.replace(str(tmp_path), str(self.path))
            try:
                os.chmod(str(self.path), 0o600)
            except OSError:
                pass
        except Exception as e:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            from ..exception.SecretStorageException import SecretStorageException
            raise SecretStorageException(f"Failed to persist storage file at {self.path}: {e}")

    def get_item(self, key: str) -> Optional[str]:
        with self._lock:
            return self._store.get(key)

    def set_item(self, key: str, value: str) -> None:
        with self._lock:
            self._store[key] = str(value)
            self._persist()

    def remove_item(self, key: str) -> bool:
        with self._lock:
            if key in self._store:
                del self._store[key]
                self._persist()
                return True
            return False

    def keys(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())
