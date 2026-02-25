# -*- coding: utf-8 -*-
from .Mutation import Mutation


class MutationActiveSession(Mutation):
    """
    Mutation for declaring an active User Session with a given MetaAsset
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        self.default_query = '''mutation(
            $bundleHash: String!,
            $metaType: String!,
            $metaId: String!,
            $ipAddress: String,
            $browser: String,
            $osCpu: String,
            $resolution: String,
            $timeZone: String,
            $json: String ) {
            ActiveSession(
                bundleHash: $bundleHash,
                metaType: $metaType,
                metaId: $metaId,
                ipAddress: $ipAddress,
                browser: $browser,
                osCpu: $osCpu,
                resolution: $resolution,
                timeZone: $timeZone,
                json: $json
            ) @fields
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
        from ..response.ResponseActiveSession import ResponseActiveSession
        return ResponseActiveSession(self, response)