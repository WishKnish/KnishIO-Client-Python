# -*- coding: utf-8 -*-
from .Query import Query


class QueryToken(Query):
    """
    Query for getting the token info
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        self.default_query = '''query( $slug: String, $slugs: [ String! ], $limit: Int, $order: String ) {
            Token( slug: $slug, slugs: $slugs, limit: $limit, order: $order ) {
                slug,
                name,
                fungibility,
                supply,
                decimals,
                amount,
                icon,
            }
        }'''
        
        self.query = query or self.default_query
    
    def create_response(self, response: dict):
        from ..response.Response import Response
        return Response(self, response)