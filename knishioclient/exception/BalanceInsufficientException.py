# -*- coding: utf-8 -*-

from .BaseError import BaseError


class BalanceInsufficientException(BaseError):
    """
    Class BalanceInsufficientException
    """
    def __init__(self, message: str = 'Insufficient balance for requested transfer', code: int = 1, *args) -> None:
        super(BalanceInsufficientException, self).__init__(message, code, *args)