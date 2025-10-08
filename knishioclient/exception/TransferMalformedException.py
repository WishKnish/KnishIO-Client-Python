# -*- coding: utf-8 -*-

from .BaseError import BaseError


class TransferMalformedException(BaseError):
    """
    Class TransferMalformedException
    """
    def __init__(self, message: str = 'Token transfer atoms are malformed', code: int = 1, *args) -> None:
        super(TransferMalformedException, self).__init__(message, code, *args)