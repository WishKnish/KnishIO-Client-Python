# -*- coding: utf-8 -*-
from .MutationProposeMolecule import MutationProposeMolecule


class MutationCreateIdentifier(MutationProposeMolecule):
    def fill_molecule(self, type0, contact, code):
        self.molecule().init_identifier_creation(type0, contact, code)
        self.molecule().sign()
        self.molecule().check()