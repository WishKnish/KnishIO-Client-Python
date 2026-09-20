# -*- coding: utf-8 -*-
from ..response import ResponseRequestAuthorization
from .MutationProposeMolecule import MutationProposeMolecule


class MutationRequestAuthorization(MutationProposeMolecule):
    def fill_molecule(self, encrypt: bool = False):
        self.molecule().init_authorization(encrypt)
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response: dict):
        return ResponseRequestAuthorization(self, response)