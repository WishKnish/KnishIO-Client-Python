# -*- coding: utf-8 -*-
"""
BatchIdException module
"""

from .BaseError import BaseError


class BatchIdException(BaseError):
    """
    Exception raised when there's an issue with batch ID handling.
    """
    
    def __init__(self, message: str = "Invalid or missing batch ID"):
        """
        Initialize BatchIdException.
        
        Args:
            message: The error message
        """
        super().__init__(message)