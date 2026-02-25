# -*- coding: utf-8 -*-
from knishioclient import query
from ..response import ResponseLinkIdentifier


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
        return ResponseLinkIdentifier(self, response)