# -*- coding: utf-8 -*-
"""
PolicyInvalidException module
"""

from .BaseError import BaseError


class PolicyInvalidException(BaseError):
    """
    Exception raised when a policy is invalid or violates constraints.
    """
    
    def __init__(self, message: str = "Invalid policy configuration"):
        """
        Initialize PolicyInvalidException.
        
        Args:
            message: The error message
        """
        super().__init__(message)