# -*- coding: utf-8 -*-
from ..response import ResponseProposeMolecule
from ..models import Molecule
from .Mutation import Mutation


class MutationProposeMolecule(Mutation):
    def __init__(self, knish_io_client: 'KnishIOClient', molecule: Molecule, query: str = None):
        super(MutationProposeMolecule, self).__init__(knish_io_client, query)
        self.default_query = 'mutation( $molecule: MoleculeInput! ) { ProposeMolecule( molecule: $molecule ) @fields }'
        self.fields = {
            'molecularHash': None,
            'height': None,
            'depth': None,
            'status': None,
            'reason': None,
            'payload': None,
            'createdAt': None,
            'receivedAt': None,
            'processedAt': None,
            'broadcastedAt': None,
        }
        self.__molecule = molecule
        self.__remainder_wallet = None
        self.query = query or self.default_query

    def molecule(self):
        return self.__molecule

    def compiled_variables(self, variables: dict = None):
        variables = super(MutationProposeMolecule, self).compiled_variables(variables)
        variables.update({"molecule": self.molecule()})
        return variables

    def create_response(self, response: dict):
        return ResponseProposeMolecule(self, response)

    def remainder_wallet(self):
        return self.__remainder_wallet

    def execute(self, variables: dict = None, fields: dict = None):
        return super(MutationProposeMolecule, self).execute(self.compiled_variables(variables), fields)