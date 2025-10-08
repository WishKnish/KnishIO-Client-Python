# -*- coding: utf-8 -*-

from .BaseError import BaseError


class TransferRemainderException(BaseError):
    """
    Class TransferRemainderException
    """
    def __init__(self, message: str = 'Invalid remainder provided', code: int = 1, *args) -> None:
        super(TransferRemainderException, self).__init__(message, code, *args)