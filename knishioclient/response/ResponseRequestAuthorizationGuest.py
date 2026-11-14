# -*- coding: utf-8 -*-
from .Response import Response
from ..exception import InvalidResponseException


class ResponseRequestAuthorizationGuest(Response):
    """
    Response for guest auth mutation
    """
    
    def data_key(self):
        return 'AccessToken'
    
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
    
    def payload_key(self, key: str):
        """
        Returns the authorization key
        
        :param key: str
        :return: Any
        :raises InvalidResponseException: If key not found in payload
        """
        payload = self.payload()
        if payload is None or key not in payload:
            raise InvalidResponseException(f"ResponseRequestAuthorizationGuest::payload_key() - '{key}' key is not found in the payload!")
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
        
        :return: Any
        """
        return self.payload_key('time')
    
    def pub_key(self):
        """
        Returns the validator's ML-KEM public key (the mutation selects ``pubkey``; ``key`` is the
        older name)

        :return: str
        """
        payload = self.payload() or {}
        if 'pubkey' in payload:
            return payload['pubkey']
        return self.payload_key('key')

    def encrypt(self):
        """
        Returns encrypt flag, or None when the reply does not carry one (the mutation does not
        select it)

        :return: Any
        """
        return (self.payload() or {}).get('encrypt')