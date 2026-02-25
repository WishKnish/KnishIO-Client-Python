# -*- coding: utf-8 -*-

from typing import List, Dict
from json import JSONDecodeError, loads


class TokenUnit:
    def __init__(self, id: str, name: str, metas: Dict = None):
        self.id: str = id
        self.name: str = name
        self.metas: Dict = metas or {}

    @classmethod
    def create_from_graph_ql(cls, data: "TokenUnit" | Dict) -> "TokenUnit":
        if isinstance(data, cls):
            return cls(data.id, data.name, data.metas)
        metas = data["metas"] or {}
        if isinstance(metas, str):
            try:
                metas = loads(metas)
            except JSONDecodeError:
                metas = {}
        return cls(data["id"], data["name"], metas)

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