# -*- coding: utf-8 -*-
from typing import Union
from .MutationProposeMolecule import MutationProposeMolecule


class MutationRequestTokens(MutationProposeMolecule):
    def fill_molecule(self, token_slug: str, requested_amount: Union[int, float], meta_type: Union[str, bytes],
                      meta_id: Union[str, bytes, int, float], metas: Union[list, dict] = None):
        data_metas = metas or {}
        self.molecule().init_token_request(token_slug, requested_amount, meta_type, meta_id, data_metas)
        self.molecule().sign()
        self.molecule().check()