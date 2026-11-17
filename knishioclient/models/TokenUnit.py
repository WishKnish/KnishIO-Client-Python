# -*- coding: utf-8 -*-

from typing import List, Dict
from json import loads


def _reject_constant(name):
    # JS JSON.parse rejects NaN, Infinity and -Infinity, which json.loads accepts.
    raise ValueError(f"TokenUnit metas is not JSON: {name}")


class TokenUnit:
    def __init__(self, id: str, name: str, metas: Dict = None):
        self.id: str = id
        self.name: str = name
        # JS `metas || {}`: a falsy value becomes {}, but an empty list stays a list.
        self.metas: Dict = metas if (metas or isinstance(metas, list)) else {}

    @classmethod
    def create_from_graph_ql(cls, data: "TokenUnit" | Dict) -> "TokenUnit":
        if isinstance(data, cls):
            return cls(data.id, data.name, data.metas)
        metas = data.get("metas") or {}
        if isinstance(metas, str):
            # As JS JSON.parse: text that is not JSON raises (json.JSONDecodeError is a ValueError).
            metas = loads(metas, parse_constant=_reject_constant)
        # Defensive: the validator stores stackable units id-only at genesis (name is an
        # empty string via COALESCE; metas may be null) — use .get() so a missing key
        # doesn't KeyError.
        return cls(data.get("id"), data.get("name") or "", metas)

    @classmethod
    def create_from_db(cls, data: List) -> "TokenUnit":
        return cls(data[0], data[1], data[2] if len(data) > 2 else {})

    def get_fragment_zone(self):
        return self.metas.get("fragmentZone", None)

    def get_fused_token_units(self):
        return self.metas.get("fusedTokenUnits", None)

    def to_data(self) -> List:
        return [self.id, self.name, self.metas]

    def to_graph_ql_response(self) -> Dict:
        return {"id": self.id, "name": self.name, "metas": self.metas}