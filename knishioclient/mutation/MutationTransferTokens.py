# -*- coding: utf-8 -*-
from .MutationProposeMolecule import MutationProposeMolecule


class MutationTransferTokens(MutationProposeMolecule):
    def fill_molecule(self, to_wallet, amount):
        self.molecule().init_value(to_wallet, amount)
        self.molecule().sign()
        self.molecule().check(self.molecule().source_wallet())