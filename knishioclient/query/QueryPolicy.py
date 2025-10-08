# -*- coding: utf-8 -*-
from .Query import Query


class QueryPolicy(Query):
    """
    Query for retrieving policy information
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        self.default_query = '''query( $metaType: String, $metaId: String, ) {
            Policy( metaType: $metaType, metaId: $metaId ) {
                molecularHash,
                position,
                metaType,
                metaId,
                conditions,
                callback,
                rule,
                createdAt
            }
        }'''
        
        self.query = query or self.default_query
    
    def create_response(self, response: dict):
        from ..response.Response import Response
        return Response(self, response)