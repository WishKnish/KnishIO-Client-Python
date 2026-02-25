# -*- coding: utf-8 -*-
from ..models import Wallet
from .MutationProposeMolecule import MutationProposeMolecule


class MutationCreateWallet(MutationProposeMolecule):
    def fill_molecule(self, new_wallet: Wallet):
        self.molecule().init_wallet_creation(new_wallet)
        self.molecule().sign()
        self.molecule().check()