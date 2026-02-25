# -*- coding: utf-8 -*-

from .BaseError import BaseError


class TransferToSelfException(BaseError):
    """
    Class TransferToSelfException
    """
    def __init__(self, message: str = 'Sender and recipient(s) cannot be the same', code: int = 1, *args) -> None:
        super(TransferToSelfException, self).__init__(message, code, *args)