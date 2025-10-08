# -*- coding: utf-8 -*-
from .Response import Response
from ..exception import InvalidResponseException


class ResponseAuthorizationGuest(Response):
    """
    Response for Guest Authorization Request
    """
    
    def __init__(self, query, json_data):
        """
        Class constructor
        
        :param query: Query object
        :param json_data: JSON response data
        """
        super().__init__(query, json_data, data_key='data.AccessToken')
    
    def reason(self):
        """
        Returns the reason for rejection
        
        :return: str
        """
        return 'Invalid response from server'
    
    def success(self):
        """
        Returns whether molecule was accepted or not
        
        :return: bool
        """
        return self.payload() is not None
    
    def payload(self):
        """
        Returns a wallet with balance
        
        :return: dict or None
        """
        return self.data()
    
    def payload_key(self, key):
        """
        Returns the authorization key
        
        :param key: Key to retrieve from payload
        :return: Value at the key
        :raises: InvalidResponseException if key not found
        """
        payload = self.payload()
        if payload is None or key not in payload:
            raise InvalidResponseException(f"ResponseAuthorizationGuest::payload_key() - '{key}' key is not found in the payload!")
        return payload[key]
    
    def token(self):
        """
        Returns the auth token
        
        :return: str
        """
        return self.payload_key('token')
    
    def time(self):
        """
        Returns timestamp
        
        :return: int or str
        """
        return self.payload_key('time')