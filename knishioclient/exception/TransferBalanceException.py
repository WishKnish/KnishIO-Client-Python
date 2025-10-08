# -*- coding: utf-8 -*-

from .BaseError import BaseError


class TransferBalanceException(BaseError):
    """
    Class TransferBalanceException
    """
    def __init__(self, message: str = 'Insufficient balance to make transfer', code: int = 1, *args) -> None:
        super(TransferBalanceException, self).__init__(message, code, *args)