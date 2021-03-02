# -*- coding: utf-8 -*-
from knishioclient import query
from knishioclient.response import (
    ResponseMolecule,
    ResponseAuthorization,
    ResponseTokenCreate,
    ResponseMetaCreate,
    ResponseIdentifier
)
from knishioclient.models import Molecule, Wallet
from typing import Union, List, Dict


class Mutation(query.Query):
    pass


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
        return ResponseMolecule(self, response)

    def remainder_wallet(self):
        return self.__remainder_wallet

    def execute(self, variables: dict = None, fields: dict = None):
        return super(MutationProposeMolecule, self).execute(self.compiled_variables(variables), fields)


class MutationCreateMeta(MutationProposeMolecule):
    def fill_molecule(self, meta_type: str, meta_id: Union[str, int], metadata: Union[List, Dict]):
        self.molecule().init_meta(metadata, meta_type, meta_id)
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response: dict):
        return ResponseMetaCreate(self, response)


class MutationCreateToken(MutationProposeMolecule):
    def fill_molecule(self, recipient_wallet: Wallet, amount, metas=None):
        data_metas = metas or {}
        self.molecule().init_token_creation(recipient_wallet, amount, data_metas)
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response):
        return ResponseTokenCreate(self, response)


class MutationClaimShadowWallet(MutationProposeMolecule):
    def fill_molecule(self, token_slug: str, batch_id):
        wallet = Wallet.create(self.molecule().secret(), token_slug, batch_id)

        self.molecule().init_shadow_wallet_claim(token_slug, wallet)
        self.molecule().sign()
        self.molecule().check()


class MutationCreateIdentifier(MutationProposeMolecule):
    def fill_molecule(self, type0, contact, code):
        self.molecule().init_identifier_creation(type0, contact, code)
        self.molecule().sign()
        self.molecule().check()


class MutationRequestAuthorization(MutationProposeMolecule):
    def fill_molecule(self):
        self.molecule().init_authorization()
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response: dict):
        return ResponseAuthorization(self, response)


class MutationRequestTokens(MutationProposeMolecule):
    def fill_molecule(self, token_slug: str, requested_amount: Union[int, float], meta_type: Union[str, bytes],
                      meta_id: Union[str, bytes, int, float], metas: Union[list, dict] = None):
        data_metas = metas or {}
        self.molecule().init_token_request(token_slug, requested_amount, meta_type, meta_id, data_metas)
        self.molecule().sign()
        self.molecule().check()


class MutationTransferTokens(MutationProposeMolecule):
    def fill_molecule(self, to_wallet, amount):
        self.molecule().init_value(to_wallet, amount)
        self.molecule().sign()
        self.molecule().check(self.molecule().source_wallet())


class MutationCreateWallet(MutationProposeMolecule):
    def fill_molecule(self, new_wallet: Wallet):
        self.molecule().init_wallet_creation(new_wallet)
        self.molecule().sign()
        self.molecule().check()


class MutationLinkIdentifier(query.Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(MutationLinkIdentifier, self).__init__(knish_io_client, query)
        self.default_query = 'mutation( $bundle: String!, $type: String!, $content: String! ) { LinkIdentifier( bundle: $bundle, type: $type, content: $content ) @fields }'
        self.fields = {
            'type': None,
            'bundle': None,
            'content': None,
            'set': None,
            'message': None,
        }
        self.query = query or self.default_query

    def create_response(self, response):
        return ResponseIdentifier(self, response)


