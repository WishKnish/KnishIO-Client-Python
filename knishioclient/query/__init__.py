# -*- coding: utf-8 -*-
import knishioclient
from knishioclient.exception import UnauthenticatedException
from knishioclient.models import Coder
from knishioclient.response import (
    Response,
    ResponseBalance,
    ResponseContinuId,
    ResponseMetaType,
    ResponseWalletBundle,
    ResponseWalletList,
    ResponseMetaTypeViaAtom
)


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

        return {
            "query": self.compiled_query(fields),
            "variables": variables,
        }

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

        if isinstance(self, knishioclient.mutation.MutationRequestAuthorization):
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

class QueryMetaTypeViaAtom(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryMetaTypeViaAtom, self).__init__(knish_io_client, query)
        self.default_query = 'query ($metaTypes: [String!], $metaIds: [String!], $values: [String!], $keys: [String!], $latest: Boolean, $filter: [MetaFilter!], $queryArgs: QueryArgs, $countBy: String, $atomValues: [String!] ) { MetaTypeViaAtom(metaTypes: $metaTypes, metaIds: $metaIds, atomValues: $atomValues, filter: $filter, latest: $latest, queryArgs: $queryArgs, countBy: $countBy) @fields }'
        self.fields = {
            "metaType": None,
            "instanceCount": {
                "key": None,
                "value": None
            },
            "instances": {
                "metaType": None,
                "metaId": None,
                "createdAt": None,
                "metas(values: $values, keys: $keys )": {
                    "molecularHash": None,
                    "position": None,
                    "key": None,
                    "value": None,
                    "createdAt": None
                }
            },
            "paginatorInfo": {
                "currentPage": None,
                "total": None
            }
        }

        self.query = query or self.default_query

    def create_response(self, response):
        return ResponseMetaTypeViaAtom(self, response)

    @classmethod
    def create_variables(
            cls,
            *,
            meta_type: str | list = None,
            meta_id: str | list = None,
            key: str = None,
            value: str = None,
            keys: list = None,
            values: list = None,
            atom_values: list = None,
            latest: bool = None,
            filter: list = None,
            query_args: dict = None,
            count_by:str = None,
    ) -> dict:
        variables = {}

        if atom_values is not None:
            variables["atomValues"] = atom_values
        if keys is not None:
            variables["keys"] = keys
        if values is not None:
            variables["values"] = values
        if meta_type is not None:
            variables["metaTypes"] = meta_type if isinstance(meta_type, list) else [meta_type]
        if meta_id is not None:
            variables["metaIds"] = meta_id if isinstance(meta_id, list) else [meta_id]
        if count_by is not None:
            variables["countBy"] = count_by
        if filter is not None:
            variables["filter"] = filter
        if key is not None and value is not None:
            if "filter" not in variables:
                variables["filter"] = []
            variables["filter"].append({
                "key": key,
                "value": value,
                "comparison": "="
            })
        if query_args is not None:
            if "limit" not in query_args or len(query_args["limit"]) == 0:
                query_args["limit"] = "*"
            variables["queryArgs"] = query_args

        variables["latest"] = latest == True

        return variables



class QueryMetaType(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryMetaType, self).__init__(knish_io_client, query)
        self.default_query = 'query( $metaType: String, $metaTypes: [ String! ], $metaId: String, $metaIds: [ String! ], $key: String, $keys: [ String! ], $value: String, $values: [ String! ], $count: String, $latest: Boolean, $filter: [ MetaFilter! ], $queryArgs: QueryArgs, $countBy: String ) { MetaType( metaType: $metaType, metaTypes: $metaTypes, metaId: $metaId, metaIds: $metaIds, key: $key, keys: $keys, value: $value, values: $values, count: $count, filter: $filter, queryArgs: $queryArgs, countBy: $countBy ) @fields }'
        self.fields = {
            "metaType": None,
            "instanceCount": {
              "key": None,
              "value": None
            },
            "instances": {
              "metaType": None,
              "metaId": None,
              "createdAt": None,
              "metas(latest:$latest)": {
                "molecularHash": None,
                "position": None,
                "key": None,
                "value": None,
                "createdAt": None
              }
            },
            "paginatorInfo": {
              "currentPage": None,
              "total": None
            }
        }

        self.query = query or self.default_query

    def create_response(self, response):
        return ResponseMetaType(self, response)

    @classmethod
    def create_variables(
            cls,
            meta_type: str | list = None,
            meta_id: str | list = None,
            key: str | list = None,
            value: str | list = None,
            latest: bool = None,
            filter: dict = None,
            query_args: dict = None,
            count: str = None,
            count_by: str = None
    ) -> dict:
        variables = {}

        if meta_type is not None:
            if isinstance(meta_type, str):
                variables.update({'metaType': meta_type})
            else:
                variables.update({'metaTypes': meta_type})
        if meta_id is not None:
            if isinstance(meta_id, str):
                variables.update({'metaId': meta_id})
            else:
                variables.update({'metaIds': meta_id})
        if key is not None:
            if isinstance(key, str):
                variables.update({'key': key})
            else:
                variables.update({'keys': key})
        if value is not None:
            if isinstance(value, str):
                variables.update({'value': key})
            else:
                variables.update({'values': key})

        variables.update({'latest': latest == True})

        if filter is not None:
            variables.update({'filter': filter})
        if query_args is not None:
            if "limit" not in query_args or len(query_args["limit"]) == 0:
                query_args["limit"] = "*"
            variables["queryArgs"] = query_args
        if count_by is not None:
            variables["countBy"] = count_by
        if count is not None:
            variables["count"] = count

        return variables


class QueryWalletBundle(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryWalletBundle, self).__init__(knish_io_client, query)
        self.default_query = 'query( $bundleHash: String, $bundleHashes: [ String! ], $key: String, $keys: [ String! ], $value: String, $values: [ String! ], $keys_values: [ MetaInput ], $latest: Boolean, $limit: Int, $order: String ) { WalletBundle( bundleHash: $bundleHash, bundleHashes: $bundleHashes, key: $key, keys: $keys, value: $value, values: $values, keys_values: $keys_values, latest: $latest, limit: $limit, order: $order ) @fields }'
        self.fields = {
            'bundleHash': None,
            'slug': None,
            'metas': {
                'molecularHash': None,
                'position': None,
                'key': None,
                'value': None,
                'createdAt': None,
            },
            # 'molecules',
            # 'wallets',
            'createdAt': None,
        }

        self.query = query or self.default_query

    @classmethod
    def create_variables(cls, bundle_hash=None, key=None, value=None, latest=True):
        variables = {
            'latest': latest,
        }

        if bundle_hash is not None:
            if isinstance(bundle_hash, (str, bytes)):
                variables.update({'bundleHash': bundle_hash})
            else:
                variables.update({'bundleHashes': bundle_hash})

        if key is not None:
            if isinstance(key, (str, bytes)):
                variables.update({'key': key})
            else:
                variables.update({'keys': key})

        if value is not None:
            if isinstance(value, (str, bytes)):
                variables.update({'value': value})
            else:
                variables.update({'values': value})

        return variables

    def create_response(self, response):
        return ResponseWalletBundle(self, response)


class QueryWalletList(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryWalletList, self).__init__(knish_io_client, query)
        self.default_query = 'query( $address: String, $bundleHash: String, $token: String, $position: String, $unspent: Boolean ) { Wallet( address: $address, bundleHash: $bundleHash, token: $token, position: $position, unspent: $unspent ) @fields }'
        self.fields = {
            'address': None,
            'bundleHash': None,
            'token': {
                'name': None,
                'amount': None,
            },
            'molecules': {
                'molecularHash': None,
                'createdAt': None,
            },
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
