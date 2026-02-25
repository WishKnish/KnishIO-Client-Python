# -*- coding: utf-8 -*-
"""
StackableUnitAmountException module
"""

from .BaseError import BaseError


class StackableUnitAmountException(BaseError):
    """
    Exception raised when stackable token units and amount conflict.
    Cannot specify both unit IDs and an amount for stackable tokens.
    """
    
    def __init__(self, message: str = "Cannot specify both stackable unit IDs and amount"):
        """
        Initialize StackableUnitAmountException.
        
        Args:
            message: The error message
        """
        super().__init__(message)