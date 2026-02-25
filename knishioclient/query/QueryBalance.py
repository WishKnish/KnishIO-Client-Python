# -*- coding: utf-8 -*-
from ..response import ResponseBalance
from .Query import Query


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