# -*- coding: utf-8 -*-
from ..response import ResponseRequestAuthorization
from .MutationProposeMolecule import MutationProposeMolecule


class MutationRequestAuthorization(MutationProposeMolecule):
    def fill_molecule(self, meta: dict = None):
        """
        :param meta: dict - the U-atom meta, e.g. ``{'encrypt': 'false', 'walletPubkey': <pubkey>}``
        """
        self.molecule().init_authorization(meta)
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response: dict):
        return ResponseRequestAuthorization(self, response)
