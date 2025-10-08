# -*- coding: utf-8 -*-
"""
AuthToken module for managing authentication tokens with expiration tracking.
Provides secure token management for KnishIO client sessions.
"""

import time
from typing import Optional, Dict, Any
from .Wallet import Wallet


class AuthToken:
    """
    Manages authentication tokens with expiration tracking and wallet association.
    """
    
    def __init__(self, 
                 token: str,
                 expires_at: int,
                 encrypt: bool = False,
                 pubkey: str = None):
        """
        Initialize an AuthToken instance.
        
        Args:
            token: The authentication token string
            expires_at: Unix timestamp when the token expires
            encrypt: Whether encryption is enabled for this session
            pubkey: Public key associated with the token
        """
        self.__token = token
        self.__expires_at = expires_at
        self.__pubkey = pubkey
        self.__encrypt = encrypt
        self.__wallet = None
    
    @classmethod
    def create(cls, data: Dict[str, Any], wallet: Wallet) -> 'AuthToken':
        """
        Factory method to create an AuthToken with an associated wallet.
        
        Args:
            data: Dictionary containing token, expiresAt, encrypt, and pubkey
            wallet: Wallet instance to associate with the token
            
        Returns:
            AuthToken instance with wallet attached
        """
        auth_token = cls(
            token=data.get('token'),
            expires_at=data.get('expiresAt'),
            encrypt=data.get('encrypt', False),
            pubkey=data.get('pubkey')
        )
        auth_token.set_wallet(wallet)
        return auth_token
    
    @classmethod
    def restore(cls, snapshot: Dict[str, Any], secret: str) -> 'AuthToken':
        """
        Restore an AuthToken from a snapshot.
        
        Args:
            snapshot: Dictionary containing token state and wallet info
            secret: Secret key to recreate the wallet
            
        Returns:
            Restored AuthToken instance
        """
        wallet = Wallet(
            secret=secret,
            token='AUTH',
            position=snapshot['wallet'].get('position'),
            characters=snapshot['wallet'].get('characters')
        )
        
        return cls.create({
            'token': snapshot['token'],
            'expiresAt': snapshot['expiresAt'],
            'pubkey': snapshot['pubkey'],
            'encrypt': snapshot.get('encrypt', False)
        }, wallet)
    
    def set_wallet(self, wallet: Wallet):
        """
        Associate a wallet with this auth token.
        
        Args:
            wallet: Wallet instance to associate
        """
        self.__wallet = wallet
    
    def get_wallet(self) -> Optional[Wallet]:
        """
        Get the associated wallet.
        
        Returns:
            The associated Wallet instance or None
        """
        return self.__wallet
    
    def get_snapshot(self) -> Dict[str, Any]:
        """
        Create a snapshot of the current auth token state.
        
        Returns:
            Dictionary containing token state and wallet info
        """
        snapshot = {
            'token': self.__token,
            'expiresAt': self.__expires_at,
            'pubkey': self.__pubkey,
            'encrypt': self.__encrypt
        }
        
        if self.__wallet:
            snapshot['wallet'] = {
                'position': self.__wallet.position,
                'characters': self.__wallet.characters
            }
        
        return snapshot
    
    def get_token(self) -> str:
        """
        Get the authentication token string.
        
        Returns:
            The token string
        """
        return self.__token
    
    def get_pubkey(self) -> Optional[str]:
        """
        Get the public key associated with the token.
        
        Returns:
            The public key string or None
        """
        return self.__pubkey
    
    def get_expire_interval(self) -> float:
        """
        Calculate the time remaining until token expiration.
        
        Returns:
            Time in milliseconds until expiration (negative if expired)
        """
        return (self.__expires_at * 1000) - (time.time() * 1000)
    
    def is_expired(self) -> bool:
        """
        Check if the token has expired.
        
        Returns:
            True if the token is expired, False otherwise
        """
        if not self.__expires_at:
            return True
        return self.get_expire_interval() < 0
    
    def get_auth_data(self) -> Dict[str, Any]:
        """
        Get authentication data for GraphQL client.
        
        Returns:
            Dictionary containing token, pubkey, and wallet
        """
        return {
            'token': self.get_token(),
            'pubkey': self.get_pubkey(),
            'wallet': self.get_wallet()
        }
    
    @property
    def token(self) -> str:
        """Property access for token."""
        return self.__token
    
    @property
    def expires_at(self) -> int:
        """Property access for expiration timestamp."""
        return self.__expires_at
    
    @property
    def encrypt(self) -> bool:
        """Property access for encryption flag."""
        return self.__encrypt
    
    @property
    def pubkey(self) -> Optional[str]:
        """Property access for public key."""
        return self.__pubkey
    
    @property
    def wallet(self) -> Optional[Wallet]:
        """Property access for wallet."""
        return self.__wallet