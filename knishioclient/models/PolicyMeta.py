# -*- coding: utf-8 -*-

from typing import List, Dict, Any
from json import dumps
from .base import Base


class PolicyMeta(Base):
    """class PolicyMeta"""

    def __init__(self, policy: Dict = None, meta_keys: List = None):
        self.policy = PolicyMeta.normalize_policy(policy or {})
        self.fill_default(meta_keys or [])

    @classmethod
    def normalize_policy(cls, policy: Dict[str, Any]) -> Dict:
        return {k: dict(v) for k, v in policy.items() if v and k in ["read", "write"]}

    def fill_default(self, meta_keys: List) -> None:
        for action in ["read", "write"]:
            policy = {v["key"]: v for v in self.policy.values() if "action" in v and v["action"] == action}
            self.policy.setdefault(action, {})
            for key in set(meta_keys) - set(policy):
                self.policy[action][key] = ["self"] if action == "write" and key not in ["characters", "pubkey"] else [
                    "all"]

    def get(self) -> Dict:
        return self.policy

    def to_json(self) -> str:
        return dumps(self.policy)