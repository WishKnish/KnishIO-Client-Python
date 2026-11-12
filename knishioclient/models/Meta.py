# -*- coding: utf-8 -*-

from typing import List, Dict
from ..libraries import strings
from .base import Base


class Meta(Base):
    """class Meta"""

    modelType: str
    modelId: str
    meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float]
    snapshotMolecule: str
    createdAt: str

    def __init__(self, model_type: str, model_id: str,
                meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float],
                snapshot_molecule: str = None) -> None:
        """
        :param model_type: str
        :param model_id: str
        :param meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float]
        :param snapshot_molecule: str default None
        """
        self.modelType = model_type
        self.modelId = model_id
        self.meta = meta
        self.snapshotMolecule = snapshot_molecule
        self.createdAt = strings.current_time_millis()

    @classmethod
    def normalize_meta(cls, metas) -> List[Dict]:
        """
        The meta as a ``[{key, value}]`` list, as JS ``Meta.normalizeMeta`` builds it: a dict's
        entries in JS property order (integer-like keys first, ascending) and every value as JS
        ``String(value)`` writes it (``True`` -> ``"true"``, ``10.0`` -> ``"10"``), ``None`` kept.

        :param metas: List or Dict
        :return: List[Dict]
        """
        if isinstance(metas, dict):
            ordered = strings._js_order({key: None for key in metas})
            return [{"key": key, "value": strings.js_string(metas[key])} for key in ordered]
        if isinstance(metas, list):
            return [
                {"key": item["key"], "value": strings.js_string(item.get("value"))}
                if isinstance(item, dict) and "key" in item else item
                for item in metas
            ]
        return metas

    @classmethod
    def aggregate_meta(cls, metas: List[Dict]) -> Dict:
        """
        :param metas: List[Dict]
        :return: Dict
        """
        aggregate = {}

        for meta in metas:
            if "key" in meta:
                aggregate.update({meta["key"]: meta["value"]})
            else:
                aggregate.update(meta)

        return aggregate