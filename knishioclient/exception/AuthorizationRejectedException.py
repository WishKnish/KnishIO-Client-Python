# -*- coding: utf-8 -*-
"""
AuthorizationRejectedException module
"""

from .BaseError import BaseError


class AuthorizationRejectedException(BaseError):
    """
    Exception raised when authorization is rejected by the server.
    """
    
    def __init__(self, message: str = "Authorization has been rejected"):
        """
        Initialize AuthorizationRejectedException.
        
        Args:
            message: The error message
        """
        super().__init__(message)