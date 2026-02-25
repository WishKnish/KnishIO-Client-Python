# -*- coding: utf-8 -*-
from ..response import ResponseCreateToken
from ..models import Wallet
from .MutationProposeMolecule import MutationProposeMolecule


class MutationCreateToken(MutationProposeMolecule):
    def fill_molecule(self, recipient_wallet: Wallet, amount, metas=None):
        data_metas = metas or {}
        self.molecule().init_token_creation(recipient_wallet, amount, data_metas)
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response):
        return ResponseCreateToken(self, response)