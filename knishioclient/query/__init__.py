# -*- coding: utf-8 -*-
from knishioclient.response import (
    Response,
    ResponseBalance,
    ResponseContinuId,
    ResponseMolecule,
    ResponseAuthentication,
    ResponseIdentifier,
    ResponseMetaType,
    ResponseTokenCreate,
    ResponseWalletBundle,
    ResponseWalletList,
)
from knishioclient.models import Molecule, Coder, Wallet
from knishioclient.exception import UnauthenticatedException


class Query(object):
    query: str
    default_query: str
    fields: dict
    __variables: dict

    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        self.__variables = {}
        self.fields = {}
        self.default_query = ''
        self.query = query or self.default_query
        self.__request = None
        self.__response = None
        self.knishIO = knish_io_client

    def get_knish_io_client(self):
        return self.knishIO

    def client(self):
        return self.knishIO.client()

    def request(self):
        return self.__request

    def response(self):
        return self.__response

    def execute(self, variables: dict = None, fields: dict = None):
        self.__request = self.create_request(variables, fields)
        response = self.client().send(self.__request)
        self.__response = self.create_response_raw(response)
        return self.response()

    def create_response_raw(self, response: dict):
        return self.create_response(response)

    def create_response(self, response: dict):
        return Response(self, response)

    def create_request(self, variables: dict = None, fields: dict = None):
        self.__variables = self.compiled_variables(variables)
        return Coder().encode(self.get_request_body(fields, self.variables()))

    def compiled_variables(self, variables: dict = None):
        return variables or {}

    def compiled_query(self, fields: dict = None):
        if fields is not None:
            self.fields = fields

        return self.query.replace('@fields', self.compiled_fields(self.fields))

    def compiled_fields(self, fields: dict):
        return '{%s}' % ','.join(
            [key if fields[key] is None else '%s%s' % (key, self.compiled_fields(fields[key])) for key in fields.keys()]
        )

    def url(self):
        return self.knishIO.url()

    def variables(self):
        return self.__variables

    def get_request_body(self, fields, variables=None):
        target = {
            'query': self.compiled_query(fields),
            'variables': variables,
        }

        if isinstance(self, QueryAuthentication):
            return target

        wallet = self.knishIO.get_authorization_wallet()
        server_key = self.knishIO.get_server_key()

        if None not in [wallet, server_key]:
            return wallet.encrypt_my_message(target, server_key)

        raise UnauthenticatedException('Unauthorized query')


class QueryBalance(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryBalance, self).__init__(knish_io_client, query)
        self.default_query = 'query( $address: String, $bundleHash: String, $token: String, $position: String ) { Balance( address: $address, bundleHash: $bundleHash, token: $token, position: $position ) @fields }'
        self.fields = {
            'address': None,
            'bundleHash': None,
            'tokenSlug': None,
            'batchId': None,
            'position': None,
            'amount': None,
            'characters': None,
            'pubkey': None,
            'createdAt': None,
        }
        self.query = query or self.default_query

    def create_response(self, response: dict):
        return ResponseBalance(self, response)


class QueryContinuId(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryContinuId, self).__init__(knish_io_client, query)
        self.default_query = 'query ($bundle: String!) { ContinuId(bundle: $bundle) @fields }'
        self.fields = {
            'address': None,
            'bundleHash': None,
            'tokenSlug': None,
            'position': None,
            'batchId': None,
            'characters': None,
            'pubkey': None,
            'amount': None,
            'createdAt': None,
        }
        self.query = query or self.default_query

    def create_response(self, response: dict):
        return ResponseContinuId(self, response)


class QueryMoleculePropose(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', molecule: Molecule, query: str = None):
        super(QueryMoleculePropose, self).__init__(knish_io_client, query)
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
        variables = super(QueryMoleculePropose, self).compiled_variables(variables)
        variables.update({'molecule': self.molecule()})
        return variables

    def create_response(self, response: dict):
        return ResponseMolecule(self, response)

    def remainder_wallet(self):
        return self.__remainder_wallet


class QueryAuthentication(QueryMoleculePropose):
    def fill_molecule(self):
        self.molecule().init_authentication()
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response: dict):
        return ResponseAuthentication(self, response)


class QueryIdentifierCreate(QueryMoleculePropose):
    def fill_molecule(self, type0, contact, code):
        self.molecule().init_identifier_creation(type0, contact, code)
        self.molecule().sign()
        self.molecule().check()


class QueryLinkIdentifierMutation(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryLinkIdentifierMutation, self).__init__(knish_io_client, query)
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


class QueryMetaType(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryMetaType, self).__init__(knish_io_client, query)
        self.default_query = 'query( $metaType: String, $metaTypes: [ String! ], $metaId: String, $metaIds: [ String! ], $key: String, $keys: [ String! ], $value: String, $values: [ String! ], $count: String ) { MetaType( metaType: $metaType, metaTypes: $metaTypes, metaId: $metaId, metaIds: $metaIds, key: $key, keys: $keys, value: $value, values: $values, count: $count ) @fields }'
        self.fields = {
            'metaType': None,
            'instances': {
                'metaType': None,
                'metaId': None,
                'createdAt': None,
                'metas': {
                    'molecularHash': None,
                    'position': None,
                    'metaType': None,
                    'metaId': None,
                    'key': None,
                    'value': None,
                    'createdAt': None,
                },
                'atoms': {
                    'molecularHash': None,
                    'position': None,
                    'isotope': None,
                    'walletAddress': None,
                    'tokenSlug': None,
                    'batchId': None,
                    'value': None,
                    'index': None,
                    'metaType': None,
                    'metaId': None,
                    'otsFragment': None,
                    'createdAt': None,
                },
                'molecules': {
                    'molecularHash': None,
                    'cellSlug': None,
                    'bundleHash': None,
                    'status': None,
                    'height': None,
                    'createdAt': None,
                    'receivedAt': None,
                    'processedAt': None,
                    'broadcastedAt': None,
                },
            },
            'metas': {
                'molecularHash': None,
                'position': None,
                'metaType': None,
                'metaId': None,
                'key': None,
                'value': None,
                'createdAt': None,
            },
            'createdAt': None,
        }

        self.query = query or self.default_query

    def create_response(self, response):
        return ResponseMetaType(self, response)


class QueryShadowWalletClaim(QueryMoleculePropose):
    def fill_molecule(self, token, shadow_wallets: list):
        self.molecule().init_shadow_wallet_claim_atom(
            token,
            [Wallet.create(self.molecule().secret(), token, shadow_wallet.batchId) for shadow_wallet in shadow_wallets]
        )
        self.molecule().sign()
        self.molecule().check()


class QueryTokenCreate(QueryMoleculePropose):
    def fill_molecule(self, recipient_wallet: Wallet, amount, metas=None):
        data_metas = metas or {}
        self.molecule().init_token_creation(recipient_wallet, amount, data_metas)
        self.molecule().sign()
        self.molecule().check()

    def create_response(self, response):
        return ResponseTokenCreate(self, response)


class QueryTokenReceive(QueryMoleculePropose):
    def fill_molecule(self, token, value, meta_type, meta_id, metas=None):
        data_metas = metas or {}
        self.molecule().init_token_transfer(token, value, meta_type, meta_id, data_metas)
        self.molecule().sign()
        self.molecule().check()


class QueryTokenTransfer(QueryMoleculePropose):
    def fill_molecule(self, to_wallet, amount):
        self.molecule().init_value(to_wallet, amount)
        self.molecule().sign()
        self.molecule().check(self.molecule().source_wallet())


class QueryWalletBundle(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryWalletBundle, self).__init__(knish_io_client, query)
        self.default_query = 'query( $bundleHash: String, $bundleHashes: [ String! ], $key: String, $keys: [ String! ], $value: String, $values: [ String! ], $keys_values: [ MetaInput ], $latest: Boolean, $limit: Int, $skip: Int, $order: String ) { WalletBundle( bundleHash: $bundleHash, bundleHashes: $bundleHashes, key: $key, keys: $keys, value: $value, values: $values, keys_values: $keys_values, latest: $latest, limit: $limit, skip: $skip, order: $order ) @fields }'
        self.fields = {
            'bundleHash': None,
            'slug': None,
            'metas': {
                'molecularHash': None,
                'position': None,
                'metaType': None,
                'metaId': None,
                'key': None,
                'value': None,
                'createdAt': None,
            },
            # 'molecules',
            # 'wallets',
            'createdAt': None,
        }

        self.query = query or self.default_query

    def create_response(self, response):
        return ResponseWalletBundle(self, response)


class QueryWalletList(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryWalletList, self).__init__(knish_io_client, query)
        self.default_query = 'query( $address: String, $bundleHash: String, $token: String, $position: String ) { Wallet( address: $address, bundleHash: $bundleHash, token: $token, position: $position ) @fields }'
        self.fields = {
            'address': None,
            'bundleHash': None,
            'tokenSlug': None,
            'batchId': None,
            'position': None,
            'amount': None,
            'characters': None,
            'pubkey': None,
            'createdAt': None,
        }
        self.query = query or self.default_query

    def create_response(self, response):
        return ResponseWalletList(self, response)
