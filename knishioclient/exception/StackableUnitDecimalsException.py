# -*- coding: utf-8 -*-
"""
StackableUnitDecimalsException module
"""

from .BaseError import BaseError


class StackableUnitDecimalsException(BaseError):
    """
    Exception raised when stackable tokens with unit IDs have decimals.
    Stackable tokens with unit IDs must not use decimals.
    """
    
    def __init__(self, message: str = "Stackable tokens with unit IDs cannot have decimals"):
        """
        Initialize StackableUnitDecimalsException.
        
        Args:
            message: The error message
        """
        super().__init__(message)