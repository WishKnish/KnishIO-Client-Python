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
        :param metas: List or Dict
        :return: List[Dict]
        """
        if isinstance(metas, dict):
            return [{"key": key, "value": value} for key, value in metas.items()]
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