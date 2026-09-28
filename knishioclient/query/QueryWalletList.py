# -*- coding: utf-8 -*-
from ..response import ResponseWalletList
from .Query import Query


class QueryWalletList(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryWalletList, self).__init__(knish_io_client, query)
        self.default_query = 'query( $bundleHash: String, $token: String, $unspent: Boolean ) { Wallet( bundleHash: $bundleHash, token: $token, unspent: $unspent ) @fields }'
        self.fields = {
            'address': None,
            'bundleHash': None,
            'token': {
                'name': None,
                'amount': None,
            },
            'tokenSlug': None,
            'batchId': None,
            'position': None,
            'amount': None,
            'characters': None,
            'pubkey': None,
            'createdAt': None,
            'tokenUnits': {
                'id': None,
                'name': None,
                'metas': None,
            },
        }
        self.query = query or self.default_query

    def create_response(self, response):
        return ResponseWalletList(self, response)