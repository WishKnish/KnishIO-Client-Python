# -*- coding: utf-8 -*-
from knishioclient.response import (
    Response,
    ResponseBalance,
    ResponseContinuId,
    ResponseMolecule,
    ResponseAuthentication
)
from knishioclient.models import Molecule, Coder


class Query(object):
    client: 'HttpClient'
    query: str
    default_query: str
    fields: dict
    __variables: dict

    def __init__(self, client: 'HttpClient', query: str = None):
        self.__variables = {}
        self.fields = {}
        self.default_query = ''
        self.client = client
        self.query = query or self.default_query
        self.__request = None
        self.__response = None

    def request(self):
        return self.__request

    def response(self):
        return self.__response

    def execute(self, variables: dict = None, fields: dict = None):
        self.__request = self.create_request(variables, fields)
        response = self.client.send(self.__request)
        self.__response = self.create_response_raw(response)
        return self.response()

    def create_response_raw(self, response: dict):
        return self.create_response(response)

    def create_response(self, response: dict):
        return Response(self, response)

    def create_request(self, variables: dict = None, fields: dict = None):
        self.__variables = self.compiled_variables(variables)

        return Coder().encode({
            'query': self.compiled_query(fields),
            'variables': self.variables(),
        })

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
        return self.client.get_url()

    def variables(self):
        return self.__variables


class QueryBalance(Query):
    def __init__(self, client: 'HttpClient', query: str = None):
        super(QueryBalance, self).__init__(client, query)
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
    def __init__(self, client: 'HttpClient', query: str = None):
        super(QueryContinuId, self).__init__(client, query)
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
    def __init__(self, client: 'HttpClient', molecule: Molecule, query: str = None):
        super(QueryMoleculePropose, self).__init__(client, query)
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
    def __init__(self, client: 'HttpClient', query: str = None):
        super(QueryLinkIdentifierMutation, self).__init__(client, query)


