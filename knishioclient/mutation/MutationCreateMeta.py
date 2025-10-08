# -*- coding: utf-8 -*-
from typing import Union, List, Dict
from ..response import ResponseCreateMeta
from .MutationProposeMolecule import MutationProposeMolecule


class MutationCreateMeta(MutationProposeMolecule):
    def fill_molecule(self, meta_type: str, meta_id: Union[str, int], metadata: Union[List, Dict], policy: Dict = None):
        self.molecule().init_meta(meta=metadata, meta_type=meta_type, meta_id=meta_id, policy=policy)
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response: dict):
        return ResponseCreateMeta(self, response)