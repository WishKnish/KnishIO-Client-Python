# -*- coding: utf-8 -*-

from typing import List, Dict, Any
from .base import Base
from ..libraries import strings


class PolicyMeta(Base):
    """class PolicyMeta"""

    def __init__(self, policy: Dict = None, meta_keys: List = None):
        self.policy = PolicyMeta.normalize_policy(policy or {})
        self.fill_default(meta_keys or [])

    @classmethod
    def normalize_policy(cls, policy: Dict[str, Any]) -> Dict:
        # JS PolicyMeta.normalizePolicy: keep every read/write entry that is not null.
        return {k: dict(v) for k, v in policy.items() if v is not None and k in ("read", "write")}

    def fill_default(self, meta_keys: List) -> None:
        # JS PolicyMeta.fillDefault: in meta-key order, fill only entries that are missing.
        for action in ("read", "write"):
            self.policy.setdefault(action, {})
            for key in meta_keys:
                if not self.policy[action].get(key):
                    self.policy[action][key] = ["self"] if action == "write" and key not in ["characters", "pubkey"] \
                        else ["all"]

    def get(self) -> Dict:
        return self.policy

    def to_json(self) -> str:
        return strings.js_json_stringify(self.policy)