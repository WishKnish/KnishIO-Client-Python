# -*- coding: utf-8 -*-
from ..response import ResponseContinuId
from .Query import Query


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