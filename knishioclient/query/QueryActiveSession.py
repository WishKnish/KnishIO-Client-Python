# -*- coding: utf-8 -*-
from .Query import Query


class QueryActiveSession(Query):
    """
    Query for retrieving a list of active User Sessions
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        self.default_query = '''query ActiveUserQuery ($bundleHash:String, $metaType: String, $metaId: String) {
            ActiveUser (bundleHash: $bundleHash, metaType: $metaType, metaId: $metaId) @fields
        }'''
        
        self.fields = {
            'bundleHash': None,
            'metaType': None,
            'metaId': None,
            'jsonData': None,
            'createdAt': None,
            'updatedAt': None
        }
        
        self.query = query or self.default_query
    
    def create_response(self, response: dict):
        from ..response.ResponseQueryActiveSession import ResponseQueryActiveSession
        return ResponseQueryActiveSession(self, response)