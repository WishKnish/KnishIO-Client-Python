# -*- coding: utf-8 -*-
from ..response import ResponseWalletList
from .Query import Query


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