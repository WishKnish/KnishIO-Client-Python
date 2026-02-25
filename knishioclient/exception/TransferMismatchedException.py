# -*- coding: utf-8 -*-

from .BaseError import BaseError


class TransferMismatchedException(BaseError):
    """
    Class TransferMismatchedException
    """
    def __init__(self, message: str = 'Token transfer slugs are mismached', code: int = 1, *args) -> None:
        super(TransferMismatchedException, self).__init__(message, code, *args)