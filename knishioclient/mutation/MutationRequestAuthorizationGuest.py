# -*- coding: utf-8 -*-
from .Mutation import Mutation


class MutationRequestAuthorizationGuest(Mutation):
    """
    Mutation for requesting guest authorization token
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        self.default_query = '''mutation( $cellSlug: String, $pubkey: String, $encrypt: Boolean ) {
            AccessToken( cellSlug: $cellSlug, pubkey: $pubkey, encrypt: $encrypt ) @fields
        }'''
        
        self.fields = {
            'token': None,
            'pubkey': None,
            'expiresAt': None
        }
        
        self.query = query or self.default_query
    
    def create_response(self, response: dict):
        from ..response.ResponseRequestAuthorizationGuest import ResponseRequestAuthorizationGuest
        return ResponseRequestAuthorizationGuest(self, response)